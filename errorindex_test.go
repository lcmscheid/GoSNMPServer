package GoSNMPServer

import (
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/pkg/errors"
)

// TestErrorIndexNamesTheFailingVarbind checks that an error Response points
// error-index at the variable binding that caused it, counting from 1 (RFC 3416
// §4.2.1, §4.2.2, §4.2.3, §4.2.5, §4.2.7). Zero is what a successful Response carries.
//
// The failing varbind is always the second one in the request, while the item
// that fails sits fourth in the OID table, so an index taken from the table
// rather than from the request shows up.
func TestErrorIndexNamesTheFailingVarbind(t *testing.T) {
	ok := func() (interface{}, error) { return Asn1IntegerWrap(1), nil }
	fails := func() (interface{}, error) { return nil, errors.New("TestError") }
	set := func(interface{}) error { return nil }
	failSet := func(interface{}) error { return errors.New("TestError") }
	trap := func(bool, gosnmp.SnmpPDU) (interface{}, error) { return Asn1IntegerWrap(1), nil }
	failTrap := func(bool, gosnmp.SnmpPDU) (interface{}, error) { return nil, errors.New("TestError") }

	master := &MasterAgent{
		Logger:         NewDiscardLogger(),
		SecurityConfig: SecurityConfig{AuthoritativeEngineBoots: 1},
		SubAgents: []*SubAgent{{
			CommunityIDs:        []string{"public"},
			UserErrorMarkPacket: true,
			OIDs: []*PDUValueControlItem{
				{OID: "1.2.3.0", Type: gosnmp.Integer, OnGet: ok, OnSet: set, OnTrap: trap},
				{OID: "1.2.3.1", Type: gosnmp.Integer, OnGet: ok, OnSet: set, OnTrap: trap},
				{OID: "1.2.3.2", Type: gosnmp.Integer, OnGet: ok, OnTrap: trap}, // read-only
				{OID: "1.2.3.3", Type: gosnmp.Integer, OnGet: fails, OnSet: failSet, OnTrap: failTrap},
			},
		}},
	}
	if err := master.ReadyForWork(); err != nil {
		t.Fatal(err)
	}

	integer := func(oid string) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Integer, Value: 1}
	}
	cases := []struct {
		name         string
		pdu          gosnmp.PDUType
		nonRepeaters uint8
		maxReps      uint32
		vars         []gosnmp.SnmpPDU
		wantErr      gosnmp.SNMPError
	}{
		{name: "get", pdu: gosnmp.GetRequest,
			vars:    []gosnmp.SnmpPDU{integer("1.2.3.1"), integer("1.2.3.3")},
			wantErr: gosnmp.GenErr},
		{name: "getnext", pdu: gosnmp.GetNextRequest,
			vars:    []gosnmp.SnmpPDU{integer("1.2.3.0"), integer("1.2.3.2")},
			wantErr: gosnmp.GenErr},
		{name: "getbulk non-repeater", pdu: gosnmp.GetBulkRequest, nonRepeaters: 2,
			vars:    []gosnmp.SnmpPDU{integer("1.2.3.0"), integer("1.2.3.2")},
			wantErr: gosnmp.GenErr},
		{name: "getbulk repeater", pdu: gosnmp.GetBulkRequest, maxReps: 1,
			vars:    []gosnmp.SnmpPDU{integer("1.2.3.0"), integer("1.2.3.2")},
			wantErr: gosnmp.GenErr},
		{name: "set read-only", pdu: gosnmp.SetRequest,
			vars:    []gosnmp.SnmpPDU{integer("1.2.3.1"), integer("1.2.3.2")},
			wantErr: gosnmp.NotWritable},
		{name: "set handler error", pdu: gosnmp.SetRequest,
			vars:    []gosnmp.SnmpPDU{integer("1.2.3.1"), integer("1.2.3.3")},
			wantErr: gosnmp.GenErr},
		{name: "inform handler error", pdu: gosnmp.InformRequest,
			vars:    []gosnmp.SnmpPDU{integer("1.2.3.1"), integer("1.2.3.3")},
			wantErr: gosnmp.GenErr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := master.ResponseForPkt(&gosnmp.SnmpPacket{
				Version:            gosnmp.Version2c,
				Community:          "public",
				PDUType:            tc.pdu,
				NonRepeaters:       tc.nonRepeaters,
				MaxRepetitions:     tc.maxReps,
				Variables:          tc.vars,
				SecurityParameters: &gosnmp.UsmSecurityParameters{},
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.Error != tc.wantErr || res.ErrorIndex != 2 {
				t.Fatalf("got %v at error-index %d, want %v at 2", res.Error, res.ErrorIndex, tc.wantErr)
			}
		})
	}
}
