package serviceprofile

import (
	"testing"
	"time"
)

func TestOwnershipMigrationIsManual(t *testing.T) {
	o := MigrateOwnership(nil, time.Unix(1, 0))
	if o.Ownership != Manual || o.CanReplace() {
		t.Fatal(o)
	}
}
