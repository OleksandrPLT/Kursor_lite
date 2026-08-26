package store

import (
	"database/sql"
	"time"
)

// Department supports one level of nesting (a "sub-department" — e.g.
// IT / Admin, Support / Admin) via ParentID. Nothing stops deeper
// nesting at the data level, but the UI only ever shows two levels.
type Department struct {
	ID       int64
	Name     string
	ParentID *int64
}

// Path renders "Parent / Child" using the pre-built id->name lookup
// (see ListDepartments) rather than issuing another query.
func (d Department) Path(names map[int64]string) string {
	if d.ParentID == nil {
		return d.Name
	}
	if parentName, ok := names[*d.ParentID]; ok {
		return parentName + " / " + d.Name
	}
	return d.Name
}

// Position is a flat, managed list of job titles.
type Position struct {
	ID   int64
	Name string
}

// ListDepartments returns every department, parents before children
// isn't guaranteed by this ordering alone — callers use the id->name map
// (built from this same slice) to resolve Path() regardless of order.
func (s *Store) ListDepartments() ([]Department, error) {
	rows, err := s.db.Query(`SELECT id, name, parent_id FROM departments ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Department
	for rows.Next() {
		var d Department
		var parentID sql.NullInt64
		if err := rows.Scan(&d.ID, &d.Name, &parentID); err != nil {
			return nil, err
		}
		if parentID.Valid {
			v := parentID.Int64
			d.ParentID = &v
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// CreateDepartment inserts a department (or sub-department, if parentID
// is non-nil).
func (s *Store) CreateDepartment(name string, parentID *int64) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO departments (name, parent_id, created_at) VALUES (?, ?, ?)`,
		name, parentID, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DeleteDepartment removes a department. Children are promoted to
// top-level (their parent_id cleared) and any accounts pointing at it
// have department_id cleared — deleting a department never deletes
// people or sub-departments.
func (s *Store) DeleteDepartment(id int64) error {
	if _, err := s.db.Exec(`UPDATE departments SET parent_id = NULL WHERE parent_id = ?`, id); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE users SET department_id = NULL WHERE department_id = ?`, id); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM departments WHERE id = ?`, id)
	return err
}

// ListPositions returns every position, alphabetically.
func (s *Store) ListPositions() ([]Position, error) {
	rows, err := s.db.Query(`SELECT id, name FROM positions ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Position
	for rows.Next() {
		var p Position
		if err := rows.Scan(&p.ID, &p.Name); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CreatePosition inserts a position.
func (s *Store) CreatePosition(name string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO positions (name, created_at) VALUES (?, ?)`,
		name, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DeletePosition removes a position; accounts pointing at it have
// position_id cleared rather than being touched otherwise.
func (s *Store) DeletePosition(id int64) error {
	if _, err := s.db.Exec(`UPDATE users SET position_id = NULL WHERE position_id = ?`, id); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM positions WHERE id = ?`, id)
	return err
}
