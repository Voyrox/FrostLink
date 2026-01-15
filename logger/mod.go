package logger

import (
	"fmt"
	"time"

	"github.com/fatih/color"
)

func SystemLog(logType, event, message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	grey := color.New(color.FgHiBlack).SprintFunc()

	switch logType {
	case "error":
		fmt.Printf("[%s] [%s] - %s\n", grey(timestamp), color.RedString(event), message)
	case "success":
		fmt.Printf("[%s] [%s] - %s\n", grey(timestamp), color.GreenString(event), message)
	case "info":
		fmt.Printf("[%s] [%s] - %s\n", grey(timestamp), color.BlueString(event), message)
	default:
		fmt.Printf("[%s] [%s] - %s\n", grey(timestamp), color.WhiteString(event), message)
	}
}
