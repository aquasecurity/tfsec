package scanner

import (
	"os"
	"sort"
	"strconv"

	"github.com/olekukonko/tablewriter"
)

type StatisticsItem struct {
	RuleID          RuleCode
	RuleDescription RuleSummary
	Link            string
	Count           int
}

type Statistics []StatisticsItem

func SortStatistics(statistics Statistics) Statistics {
	sort.Slice(statistics, func(i, j int) bool {
		return statistics[i].Count > statistics[j].Count
	})
	return statistics
}

func (statistics Statistics) PrintStatisticsTable() {
	table := tablewriter.NewWriter(os.Stdout)
	statistics = SortStatistics(statistics)
	table.SetHeader([]string{"Rule ID", "Description", "Link", "Count"})
	table.SetRowLine(true)

	for _, item := range statistics {
		table.Append([]string{string(item.RuleID),
			string(item.RuleDescription),
			item.Link,
			strconv.Itoa(item.Count)})
	}

	table.Render()
}

func AddStatisticsCount(StatisticsSlice Statistics, result Result) Statistics {
	for i, statistics := range StatisticsSlice {
		if statistics.RuleID == result.RuleID {
			StatisticsSlice[i].Count += 1
			return StatisticsSlice
		}
	}
	StatisticsSlice = append(StatisticsSlice, StatisticsItem{RuleID: result.RuleID,
		RuleDescription: result.RuleDescription,
		Link:            result.Link,
		Count:           1,
	})

	return StatisticsSlice
}
