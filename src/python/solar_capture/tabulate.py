'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

import string


def stringify_table(rows):
    return [[str(f) for f in row] for row in rows]


def is_int(str):
    try:
        int(str)
        return True
    except:
        return False


def auto_justify_col(col, width):
    if min(map(is_int, col[1:])):
        # All fields (possibly excepting first) are integers.

        return [f.rjust(width) for f in col]
    else:
        return [f.ljust(width) for f in col]


def justify_col_by_field(justify_field):
    def justify_col(col, width):
        return [justify_field(f, width) for f in col]
    return justify_col

def pad_table(rows, justify_field=None, justify_col=None, col_widths=None):
    if justify_field is None and justify_col is None:
        justify_col = auto_justify_col

    # This is like zip(*rows) except it handles non-uniform row lengths.
    ncols = max(len(row) for row in rows)
    cols = [[i<len(row) and row[i] or '' for row in rows] \
                for i in range(ncols)]

    widths = [max(len(f) for f in col) for col in cols]
    if col_widths:
        widths = list(map(max, widths, col_widths))
        for i, w in enumerate(widths):
            col_widths[i] = w

    if not justify_col:
        if hasattr(justify_field, '__getitem__'):
            justify_col = map(justify_col_by_field, justify_field)
        else:
            justify_col = justify_col_by_field(justify_field)
    if not hasattr(justify_col, '__getitem__'):
        justify_col = [justify_col] * ncols

    cols = [justify_col[i](col, widths[i]) for i, col in enumerate(cols)]
    return zip(*cols)


def fmt_table(rows, colsep=' ', rowsep='\n', pad=True, justify_field=None,
              justify_col=None, col_widths=None):
    rows = stringify_table(rows)
    if pad:
        rows = pad_table(rows, justify_field=justify_field,
                         justify_col=justify_col, col_widths=col_widths)
    return rowsep.join(colsep.join(row) for row in rows)


def playpen():
    test_data = [
        ['name',   'age', 'height'],
        ['david',   37, 180243],
        ['abbie',   38, 150242342],
        ['cameron', 5,  110],
        ]

    widths = [0] * 3
    print( fmt_table(test_data, col_widths=widths) )

    l = "".ljust
    r = "".rjust
    print( fmt_table(test_data, col_widths=widths,
                    justify_field=[r, l, l], colsep=' | ') )

#playpen()
