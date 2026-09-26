package authsession

// AdminClaim is the claim that makes a user an admin.
const AdminClaim = "admin"

type claim struct {
	Name  string
	Value string
}

type Claims []claim

func (c *Claims) Add(name string, value string) {
	*c = append(*c, claim{
		Name:  name,
		Value: value,
	})
}

func (c *Claims) Contains(claim string) bool {
	for _, curr := range *c {
		if curr.Name == claim {
			return true
		}
	}
	return false
}

func (c *Claims) Has(claim string, value string) bool {
	for _, curr := range *c {
		if curr.Name == claim {
			if curr.Value == value {
				return true
			}
		}
	}
	return false
}

func (c *Claims) IsAdmin() bool {
	return c.Has(AdminClaim, "true")
}

func (c *Claims) MakeAdmin() {
	if c == nil {
		return
	}
	c.Add(AdminClaim, "true")
}
