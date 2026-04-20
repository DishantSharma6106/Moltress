package main

import (
	"log"

	tea "github.com/charmbracelet/bubbletea"

	"moltress/cli/internal/app"
)

func main() {
	model := app.NewModel(&app.DemoSource{})
	program := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		log.Fatal(err)
	}
}
