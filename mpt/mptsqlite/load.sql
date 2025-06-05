SELECT
    label,
    label_bit_len,
    left_label,
    left_label_bit_len,
    right_label,
    right_label_bit_len,
    hash
FROM
    nodes
WHERE
    label = ?
    AND label_bit_len = ?;
