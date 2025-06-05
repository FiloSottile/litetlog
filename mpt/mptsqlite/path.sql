WITH RECURSIVE path(
    label,
    label_bit_len,
    left_label,
    left_label_bit_len,
    right_label,
    right_label_bit_len,
    hash,
    -- 0: target is on the left, 1: target is on the right, -1: target is not a child
    side,
    -- 0: not on the same side of parent as target, 1: on the same side
    onpath
) AS (
    SELECT
        label,
        label_bit_len,
        left_label,
        left_label_bit_len,
        right_label,
        right_label_bit_len,
        hash,
        sideof(
            :label,
            :label_bit_len,
            label,
            label_bit_len
        ) AS side,
        1 AS onpath
    FROM
        nodes
    WHERE
        label = :root_label
        AND label_bit_len = :root_label_bit_len
    UNION
    ALL
    SELECT
        n.label,
        n.label_bit_len,
        n.left_label,
        n.left_label_bit_len,
        n.right_label,
        n.right_label_bit_len,
        n.hash,
        sideof(
            :label,
            :label_bit_len,
            n.label,
            n.label_bit_len
        ) AS side,
        CASE
            -- as a special case, if the tree is empty and the root has two equal
            -- empty children, we record it as off-path, so it gets returned
            WHEN p.left_label = p.right_label
            AND p.left_label_bit_len = p.right_label_bit_len THEN 0
            WHEN p.side = 0
            AND n.label = p.left_label
            AND n.label_bit_len = p.left_label_bit_len THEN 1
            WHEN p.side = 1
            AND n.label = p.right_label
            AND n.label_bit_len = p.right_label_bit_len THEN 1
            ELSE 0
        END AS onpath
    FROM
        nodes n,
        path p
    WHERE
        (
            -- left child
            (
                n.label = p.left_label
                AND n.label_bit_len = p.left_label_bit_len
            )
            OR -- right child
            (
                n.label = p.right_label
                AND n.label_bit_len = p.right_label_bit_len
            )
        )
        AND -- only continue if the target is a prefix of the target
        p.side != -1
        AND -- stop at leaves
        p.label_bit_len < 256
    ORDER BY
        -- first return the sibling, then follow the path
        onpath ASC
)
SELECT
    label,
    label_bit_len,
    left_label,
    left_label_bit_len,
    right_label,
    right_label_bit_len,
    hash
FROM
    path
WHERE
    -- return the siblings of the path to the target
    onpath = 0
    OR -- and the final node which will become the sibling of the target
    -- unless it's the empty child of the root that will be replaced
    onpath = 1
    AND side = -1
    AND label_bit_len != 0
