package cli

type Runner interface {
	Init([]string) error
	Run() error
	Name() string
}
