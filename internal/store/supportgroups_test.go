package store

import "testing"

func TestNextSupportGroup(t *testing.T) {
	groups := []SupportGroup{
		{ID: 1, Name: "Line 1", Rank: 10},
		{ID: 2, Name: "Line 2", Rank: 20},
		{ID: 3, Name: "Line 3", Rank: 30},
		{ID: 4, Name: "Moderator", Rank: 40},
	}

	next := NextSupportGroup(groups, 0)
	if next == nil || next.ID != 1 {
		t.Fatalf("from rank 0 (no group yet), expected Line 1, got %+v", next)
	}

	next = NextSupportGroup(groups, 10)
	if next == nil || next.ID != 2 {
		t.Fatalf("from rank 10, expected Line 2, got %+v", next)
	}

	next = NextSupportGroup(groups, 40)
	if next != nil {
		t.Fatalf("from the highest rank, expected nil (nothing higher), got %+v", next)
	}

	// A rank that doesn't exactly match any group (e.g. a group was
	// deleted) should still find the next one above it.
	next = NextSupportGroup(groups, 15)
	if next == nil || next.ID != 2 {
		t.Fatalf("from rank 15 (between Line 1 and Line 2), expected Line 2, got %+v", next)
	}
}
