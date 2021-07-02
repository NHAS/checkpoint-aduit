package table

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type value struct {
	parts   []string
	longest int
}

type Table struct {
	name          string
	rows          int
	line          [][]value
	cellMaxWidth  []int
	lineMaxHeight []int
}

func makeValue(rn string) (val value) {
	val.parts = strings.Split(rn, "\n")
	for _, n := range val.parts {
		if len(n) > val.longest {
			val.longest = len(n)
		}
	}
	return
}

func (t *Table) updateMax(line []value) error {
	if len(line) != t.rows {
		return errors.New("Wrong size guy")
	}

	if t.cellMaxWidth == nil {
		t.cellMaxWidth = make([]int, t.rows)
	}

	height := 0
	for i, n := range line {
		if t.cellMaxWidth[i] < n.longest {
			t.cellMaxWidth[i] = n.longest
		}

		if height < len(n.parts) {
			height = len(n.parts)
		}
	}

	t.lineMaxHeight = append(t.lineMaxHeight, height)

	return nil
}

func (t *Table) AddValues(vals ...string) error {
	if len(vals) != t.rows {
		return fmt.Errorf("Error more values than exist in the row name")
	}

	var line []value
	for _, v := range vals {
		line = append(line, makeValue(v))
	}

	err := t.updateMax(line)
	if err != nil {
		return err
	}

	t.line = append(t.line, line)

	return nil
}

func (t *Table) Print() {
	t.Fprint(os.Stdout)
}

func (t *Table) Fprint(w io.Writer) {

	firstLine := true

	for n, line := range t.line {
		// X Y
		values := make([][]string, len(line))
		for x, m := range line {
			values[x] = m.parts
		}

		drawnLines := []string{}
		max := 0
		for y := 0; y < t.lineMaxHeight[n]; y++ {

			m := "|"
			for x := 0; x < len(line); x++ {
				val := ""
				if len(values[x]) > y {
					val = values[x][y]
				}
				m += fmt.Sprintf(" %-"+fmt.Sprintf("%d", t.cellMaxWidth[x])+"s |", val)
			}

			if max < len(m) {
				max = len(m)
			}

			drawnLines = append(drawnLines, m)

		}

		if firstLine {
			firstLine = false
			fmt.Fprintf(w, "%"+fmt.Sprintf("%d", max/2)+"s\n", t.name)

			fmt.Println(seperator(max))
		}

		for _, l := range drawnLines {
			fmt.Println(l)
		}

		fmt.Println(seperator(max))

	}
}

func seperator(i int) (out string) {
	for n := 0; n < i; n++ {
		out += "-"
	}

	return out
}

func NewTable(name string, rowNames ...string) (t Table, err error) {

	var line []value
	for _, name := range rowNames {
		line = append(line, makeValue(name))
	}

	t.rows = len(line)

	t.name = name

	return t, t.AddValues(rowNames...)
}
