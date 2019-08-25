import bisect

def decode(data):
    entries = data.split(',')
    for index, entry in enumerate(entries):
        if entry.startswith('_'):
            # An entry prefixed with an underscore (a reference) is the
            # ASCII representation of the zero-based integer index of a
            # prior entry in the input data, indicating that the output of
            # this entry is the output of the referenced entry
            # concatenated with the first character of the output of the
            # entry after the referenced entry.
            #
            # For example, _0 indicates that the output of this entry is
            # the output of the first entry (index 0) in the input data
            # concatenated with the first character of the output of the
            # second entry (index 1) in the input data.
            reference_index = int(entry[1:])
            if reference_index >= index:
                # Can't reference this entry or any future entry.
                raise ValueError(
                    f"Invalid back reference in entry {index}, references"
                    f" future entry {reference_index}: {data}"
                )
            reference_next_index = reference_index + 1
            reference_value = entries[reference_index]
            if reference_next_index == index:
                # If this entry is the reference_next_index, then the
                # first character of the output of this entry will also
                # be the last character of the output of this entry.
                entries[index] = reference_value + reference_value[0]
            else:
                entries[index] = reference_value + entries[reference_next_index][0]
        else:
            # An entry not prefixed by an underscore is the decimal ASCII
            # representation of a character, indicating that the output of
            # this entry is that character.
            entries[index] = chr(int(entry))
    return ''.join(entries)

def encode(data):
    entries = []
    # so we can get slices efficiently
    view = memoryview(data.encode('ascii'))
    entry_offset = []
    # to limit our back reference searches for efficiency
    first_letter_entries = {}
    i = 0
    while i < len(view):
        # get this BEFORE adding this entry, so it serves as the index without math
        entry_index = len(entry_offset)
        first_letter = view[i]
        letter_entries = first_letter_entries.get(first_letter, [])
        if not letter_entries:
            first_letter_entries[first_letter] = letter_entries
        entry_offset.append(i)
        is_reference = False
        # The length is just for sorting longest to smallest, so _ is a dummy.
        for _, j in letter_entries:
            reference_offset = entry_offset[j]
            # the referenced entry and the first character of the next entry
            length = entry_offset[j + 1] - reference_offset + 1
            if view[i:i + length] == view[reference_offset:reference_offset + length]:
                # because we're looping largest to smallest, and due to the nature
                # of the compression, there's not any concievable back reference
                # that could be better... there's only other choices with equivalent
                # results.  We prefer the earliest index of any given length due to
                # it being potentially being representable in less digits.
                entries.append(f"_{j}")
                is_reference = True
                break
        if not is_reference:
            length = 1
            entries.append(str(first_letter))  # add the ordinal, not the value
        i += length
        # there's no cmp or reverse arguments for bisect.insort()
        # so negate the length so larger lengths sort earlier
        # leave the index alone, we want the earliest index first
        bisect.insort(letter_entries, (-length, entry_index))
    return ','.join(entries)