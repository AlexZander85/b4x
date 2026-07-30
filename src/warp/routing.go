package warp

import "errors"

type MarkAllocator struct {
	next   uint32
	owners map[uint32]string
}

func NewMarkAllocator() *MarkAllocator {
	return &MarkAllocator{next: 0x4000, owners: map[uint32]string{}}
}
func (a *MarkAllocator) Allocate(owner string) (uint32, error) {
	if a == nil || owner == "" {
		return 0, errors.New("invalid mark owner")
	}
	a.next++
	if _, ok := a.owners[a.next]; ok {
		return 0, errors.New("mark collision")
	}
	a.owners[a.next] = owner
	return a.next, nil
}
func (a *MarkAllocator) Release(mark uint32) {
	if a != nil {
		delete(a.owners, mark)
	}
}

type DialPolicy struct {
	Mark                    uint32
	BindDevice, EndpointPin string
	DirectControl           bool
	ProxyEnvDisabled        bool
	Generation              uint64
}

func (p DialPolicy) Valid() bool {
	return p.Mark != 0 && p.BindDevice != "" && p.EndpointPin != "" && p.DirectControl && p.ProxyEnvDisabled && p.Generation > 0
}
func ValidateNoRecursion(policy DialPolicy, routeMark uint32) error {
	if !policy.Valid() {
		return errors.New("invalid dial policy")
	}
	if routeMark == policy.Mark {
		return errors.New("recursive route")
	}
	return nil
}
