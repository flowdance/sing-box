// Package flowlog persists per-connection flow records (source/destination,
// bytes, timing) to a SQLite database for traffic analysis.
//
// It reuses sing-box's built-in traffic counter (clashapi/trafficontrol) and
// only subscribes to its connection-closed events, so it does not touch the
// forwarding path. See flowlog.go for the event subscription.
package flowlog

import (
	"database/sql"
	"time"

	"github.com/sagernet/sing-box/common/trafficcontrol"

	_ "modernc.org/sqlite"
)

// record is one persisted flow (a closed connection lifecycle).
type record struct {
	started    int64
	ended      int64
	network    string
	srcIP      string
	srcPort    int64
	dstIP      string
	dstPort    int64
	domain     string
	upBytes    int64
	downBytes  int64
	inbound    string
	inboundTag string
	user       string
	outbound   string
}

const schema = `
-- started/ended are epoch milliseconds.
CREATE TABLE IF NOT EXISTS flows (
  started INTEGER, ended INTEGER, network TEXT,
  src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, domain TEXT,
  up_bytes INTEGER, down_bytes INTEGER, inbound TEXT, inbound_tag TEXT, user TEXT, outbound TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_started ON flows(started);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst_ip);
`

type store struct {
	db     *sql.DB
	insert *sql.Stmt
}

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	// Single connection: writes are serialized by a single consumer goroutine,
	// and this avoids SQLITE_BUSY from concurrent in-process writers. External
	// readers (e.g. the sqlite3 CLI) still read concurrently via WAL.
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	if err = migrateColumns(db); err != nil {
		db.Close()
		return nil, err
	}
	stmt, err := db.Prepare(`INSERT INTO flows (started, ended, network, src_ip, src_port, dst_ip, dst_port, domain, up_bytes, down_bytes, inbound, inbound_tag, user, outbound) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &store{db: db, insert: stmt}, nil
}

// migrateColumns adds columns introduced after the initial schema. CREATE TABLE
// IF NOT EXISTS leaves an existing table untouched, so additive ALTERs keep an
// older database writable when its schema predates a column.
func migrateColumns(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(flows)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	have := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var dflt sql.NullString
		if err = rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return err
		}
		have[name] = true
	}
	if err = rows.Err(); err != nil {
		return err
	}
	for _, c := range []struct{ name, decl string }{
		{"inbound_tag", "TEXT"},
		{"user", "TEXT"},
	} {
		if !have[c.name] {
			if _, err = db.Exec("ALTER TABLE flows ADD COLUMN " + c.name + " " + c.decl); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *store) insertBatch(batch []record) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, r := range batch {
		if _, err = tx.Stmt(s.insert).Exec(
			r.started, r.ended, r.network,
			r.srcIP, r.srcPort, r.dstIP, r.dstPort, r.domain,
			r.upBytes, r.downBytes, r.inbound, r.inboundTag, r.user, r.outbound,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// deleteOld removes flows that ended before now - retentionDays, in bounded
// batches (SQLite's DELETE...LIMIT is not always compiled in).
func (s *store) deleteOld(retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}
	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour).UnixMilli()
	for {
		res, err := s.db.Exec(`DELETE FROM flows WHERE rowid IN (SELECT rowid FROM flows WHERE ended < ? LIMIT 5000)`, cutoff)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return nil
		}
	}
}

func (s *store) close() error {
	if s.insert != nil {
		_ = s.insert.Close()
	}
	return s.db.Close()
}

// metadataToRecord maps a closed connection's tracker metadata to a persisted
// record. Upload/Download are *atomic.Int64 shared with the metadata copy
// emitted by Manager.Leave; the counter connection is already closed, so Load()
// reads the final totals safely.
func metadataToRecord(t *trafficcontrol.TrackerMetadata) record {
	md := t.Metadata
	var domain string
	if md.Domain != "" {
		domain = md.Domain
	} else {
		domain = md.Destination.Fqdn
	}
	var srcIP, dstIP string
	if md.Source.Addr.IsValid() {
		srcIP = md.Source.Addr.String()
	}
	if md.Destination.Addr.IsValid() {
		dstIP = md.Destination.Addr.String()
	}
	return record{
		started:    t.CreatedAt.UnixMilli(),
		ended:      t.ClosedAt.UnixMilli(),
		network:    md.Network,
		srcIP:      srcIP,
		srcPort:    int64(md.Source.Port),
		dstIP:      dstIP,
		dstPort:    int64(md.Destination.Port),
		domain:     domain,
		upBytes:    t.Upload.Load(),
		downBytes:  t.Download.Load(),
		inbound:    md.InboundType,
		inboundTag: md.Inbound,
		user:       md.User,
		outbound:   t.Outbound,
	}
}
