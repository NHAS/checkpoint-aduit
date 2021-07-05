package main

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"path"
	"path/filepath"
	"strings"

	"github.com/NHAS/checkpoint-audit/table"
)

type Node struct {
	Uid      string
	Name     string
	Comments string
	Type     string

	IPv4          string `json:"ipv4-address"`
	SubnetAddress string `json:"subnet4"`
	MaskLength    int    `json:"mask-length4"`
	Port          string
	Protocol      string
	Members       []string

	Edges []*Edge
}

func (n *Node) Hash() string {
	return fmt.Sprintf("%s", md5.Sum([]byte(n.Uid+n.Name+n.Type+n.IPv4+n.SubnetAddress+n.Port+n.Protocol)))
}

type Edge struct {
	Start  *Node
	End    *Node
	Method string
}

type ACLRule struct {
	Action      string
	Name        string
	SrcNegate   bool `json:"source-negate"`
	DstNegate   bool `json:"destination-negate"`
	Comments    string
	Source      []string
	Destination []string
	Type        string
	Enabled     bool
	Number      int `json:"rule-number"`
	Service     []string
}

func Bidirectional(n1 *Node, n2 *Node) {
	to := Edge{Start: n1, End: n2, Method: "Di"}
	from := Edge{Start: n2, End: n1, Method: "Di"}

	n1.Edges = append(n1.Edges, &to)
	n2.Edges = append(n2.Edges, &from)
}

func Monodirectional(to *Node, from *Node) {
	e := Edge{Start: from, End: to, Method: "Mono"}

	to.Edges = append(to.Edges, &e)
	from.Edges = append(from.Edges, &e)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func loadObjects(paths []string) (names map[string]string, objects map[string]*Node) {

	groups := []*Node{}
	networks := []*Node{}
	hosts := []*Node{}

	names = make(map[string]string)
	objects = make(map[string]*Node)

	for _, path := range paths {

		objs, err := ioutil.ReadFile(path)
		check(err)

		var jsonObjects []json.RawMessage
		check(json.Unmarshal(objs, &jsonObjects))

		//Populate all objects
		for _, v := range jsonObjects {
			var n Node
			check(json.Unmarshal(v, &n))

			if _, ok := objects[n.Uid]; ok {
				if n.Hash() != objects[n.Uid].Hash() {
					log.Fatalf("Nodes not equal\n%v\n%v", n, objects[n.Uid])
				}

				continue
			}

			objects[n.Uid] = &n

			switch n.Type {
			case "host":
				hosts = append(hosts, &n)
			case "group", "service-group":
				groups = append(groups, &n)
			case "network":
				networks = append(networks, &n)
			}

			names[n.Name] = n.Uid
		}
	}

	//Dereference objects and populate groups
	for g := range groups {
		for _, m := range groups[g].Members {
			Monodirectional(objects[m], groups[g])
		}
	}

	for n := range networks {
		for h := range hosts {
			_, netRange, err := net.ParseCIDR(fmt.Sprintf("%s/%d", networks[n].SubnetAddress, networks[n].MaskLength))
			check(err)

			if netRange.Contains(net.ParseIP(hosts[h].IPv4)) {
				Bidirectional(hosts[h], networks[n])
			}
		}
	}

	return
}

func main() {

	directory := flag.String("path", "", "Path to checkpoint exported resources")
	target := flag.String("t", "", "Target node (by name)")
	assocOnly := flag.Bool("g", false, "Associated groups/nodes/networks only, i.e dont find firewall rules")
	childrenOnly := flag.Bool("c", false, "Get all children BFS")

	flag.Parse()

	matches, err := filepath.Glob(path.Join(*directory, "*_objects.json"))
	check(err)

	namesMap, allObjects := loadObjects(matches)

	if *target == "" {
		for n := range namesMap {
			fmt.Println(n)
		}
		return
	}

	var associatedNodes []*Node
	if !*childrenOnly {
		associatedNodes = getPermissionGroups(allObjects[namesMap[*target]])
	} else {
		associatedNodes = getAllChildren(allObjects[namesMap[*target]])
	}

	t, err := table.NewTable(*target+" Belongs To", "Name", "Type", "Extra", "Comment", "UID")
	check(err)

	checkMap := make(map[string]bool)

	for _, currentNode := range associatedNodes {

		checkMap[currentNode.Uid] = true

		extraData := ""
		switch currentNode.Type {
		case "host":
			extraData = currentNode.IPv4
		case "network":
			extraData = fmt.Sprintf("%s/%d", currentNode.SubnetAddress, currentNode.MaskLength)
		case "group":
			extraData = fmt.Sprintf("Members %d", len(currentNode.Members))
		}

		t.AddValues(currentNode.Name, currentNode.Type, extraData, strings.TrimSpace(currentNode.Comments), currentNode.Uid)
	}

	t.Print()

	if *assocOnly || *childrenOnly {
		return
	}

	matches, err = filepath.Glob(path.Join(*directory, "*Security-s116.json"))

	var accessTo []ACLRule
	var accessFrom []ACLRule

	for _, p := range matches {
		aclBytes, err := ioutil.ReadFile(p)
		check(err)

		var rules []json.RawMessage
		check(json.Unmarshal(aclBytes, &rules))

	OuterLoop:
		for _, r := range rules {
			if bytes.Contains(r, []byte("access-rule")) {
				var acl ACLRule
				check(json.Unmarshal(r, &acl))
				if acl.Enabled {

					for _, uid := range acl.Source {
						applies := doesRuleApply(checkMap, allObjects, acl, uid)
						//Xor If it applies and is not negated, and if it doesnt apply but is negated
						if applies != acl.SrcNegate {
							accessTo = append(accessTo, acl)
							continue OuterLoop
						}
					}

					for _, uid := range acl.Destination {
						applies := doesRuleApply(checkMap, allObjects, acl, uid)
						if applies != acl.DstNegate {
							accessFrom = append(accessFrom, acl)
							continue OuterLoop
						}
					}

				}
			}
		}

	}

	fmt.Print("\n")

	accessToTable, _ := table.NewTable(*target+"->Target", "No.", "Src", "Dst", "Service", "Action")
	buildTable(&accessToTable, accessTo, allObjects)
	accessToTable.Print()

	fmt.Print("\n")

	accessFromTable, _ := table.NewTable("Target->"+*target, "No.", "Src", "Dst", "Service", "Action")
	buildTable(&accessFromTable, accessFrom, allObjects)
	accessFromTable.Print()

}

func getAllChildren(n *Node) (children []*Node) {
	visited := make(map[*Node]bool)

	visited[n] = true
	searchSpace := []*Node{n}

	for len(searchSpace) != 0 {
		currentNode := searchSpace[0]
		children = append(children, currentNode)
		searchSpace = searchSpace[1:]

		for _, e := range currentNode.Edges {
			if visited[e.End] {
				continue
			}

			searchSpace = append(searchSpace, e.End)
			visited[e.End] = true

		}
	}

	return
}

func getPermissionGroups(n *Node) (assoc []*Node) {
	visited := make(map[*Node]bool)

	visited[n] = true
	searchSpace := []*Node{n}
	//Only add directly connected networks and hosts
	for _, e := range n.Edges {
		if !visited[e.End] && (e.End.Type == "network" || e.End.Type == "host") {
			visited[e.End] = true
			searchSpace = append(searchSpace, e.End)
		}
	}

	for len(searchSpace) != 0 {
		currentNode := searchSpace[0]
		assoc = append(assoc, currentNode)
		searchSpace = searchSpace[1:]

		for _, e := range currentNode.Edges {
			if visited[e.Start] || currentNode.Type == "host" {
				continue
			}

			searchSpace = append(searchSpace, e.Start)
			visited[e.Start] = true

		}
	}

	return
}

func doesRuleApply(associatedObjects map[string]bool, allObjects map[string]*Node, acl ACLRule, uid string) bool {
	return (associatedObjects[uid] || allObjects[uid].Type == "CpmiAnyObject")
}

func buildTable(table *table.Table, acl []ACLRule, allObjects map[string]*Node) {
	for _, aclr := range acl {

		src := ""
		for _, v := range aclr.Source {
			if aclr.SrcNegate {
				src += "!"
			}

			src += allObjects[v].Name + "\n"

		}
		src = src[:len(src)-1]

		dst := ""
		for _, v := range aclr.Destination {
			if aclr.DstNegate {
				dst += "!"
			}

			dst += allObjects[v].Name + "\n"

		}
		dst = dst[:len(dst)-1]

		service := ""
		for _, v := range aclr.Service {
			serv := allObjects[v]

			if strings.Contains(serv.Type, "service-group") {
				service += recurseServiceGroup(serv, serv.Name, allObjects)
				continue
			}

			service += serv.Name + ":" + serv.Type
			if !strings.Contains(serv.Type, "icmp") {
				service += ":" + serv.Port
			}

			if serv.Type == "CpmiAnyObject" {
				service = "Any"
			}

			service += "\n"

		}

		err := table.AddValues(fmt.Sprintf("%d", aclr.Number), src, dst, service, allObjects[aclr.Action].Name)
		check(err)

	}

}

func recurseServiceGroup(service *Node, groupName string, allObjects map[string]*Node) string {
	services := ""
	for _, member := range service.Members {
		subservice := allObjects[member]
		if subservice.Type == "service-group" {

			services += recurseServiceGroup(subservice, subservice.Name, allObjects)

			continue
		}

		services += groupName + ":" + subservice.Name + ":" + subservice.Type
		if !strings.Contains(subservice.Type, "icmp") {
			services += ":" + subservice.Port
		}
		services += "\n"
	}

	return services
}
