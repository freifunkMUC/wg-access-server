package authsession

// AdminClaim is the claim that makes a user an admin.
const AdminClaim = "admin"

// PolicyClaim names an access policy the user is in. There is one per policy,
// so somebody can be in several.
const PolicyClaim = "policy"

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

// Values returns the values of every claim with that name, in the order they
// were added.
func (c *Claims) Values(name string) []string {
	values := []string{}
	for _, curr := range *c {
		if curr.Name == name {
			values = append(values, curr.Value)
		}
	}
	return values
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
