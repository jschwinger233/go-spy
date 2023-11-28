package proc

type Proc struct {
	pid int
}

func Get(pid int) *Proc {
	return &Proc{pid: pid}
}
