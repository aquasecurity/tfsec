package scanner

import (
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"

	"github.com/olekukonko/tablewriter"
)

type StatisticsItem struct {
	RuleID          string
	RuleDescription string
	Links           []string
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
		table.Append([]string{item.RuleID,
			item.RuleDescription,
			strings.Join(item.Links, "\n"),
			strconv.Itoa(item.Count)})
	}

	table.Render()
}

func AddStatisticsCount(StatisticsSlice Statistics, result result.Result) Statistics {
	for i, statistics := range StatisticsSlice {
		if statistics.RuleID == result.RuleID {
			StatisticsSlice[i].Count += 1
			return StatisticsSlice
		}
	}
	StatisticsSlice = append(StatisticsSlice, StatisticsItem{RuleID: result.RuleID,
		RuleDescription: result.RuleSummary,
		Links:           result.Links,
		Count:           1,
	})

	return StatisticsSlice
}
