INSERT
    OR REPLACE INTO nodes (
        label,
        label_bit_len,
        left_label,
        left_label_bit_len,
        right_label,
        right_label_bit_len,
        hash
    )
VALUES
    (?, ?, ?, ?, ?, ?, ?);
