CREATE TABLE IF NOT EXISTS nodes (
    label BLOB NOT NULL,
    label_bit_len INTEGER NOT NULL,
    left_label BLOB,
    left_label_bit_len INTEGER,
    right_label BLOB,
    right_label_bit_len INTEGER,
    hash BLOB NOT NULL,
    PRIMARY KEY (label, label_bit_len)
) WITHOUT ROWID;
