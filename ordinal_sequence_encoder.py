#!/usr/bin/env python3
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
    # So we can get slices efficiently
    data = memoryview(data.encode('ascii'))
    entry_offset = []
    # To limit our back reference searches for efficiency
    entries_with_first_character = {}
    offset = 0
    while offset < len(data):
        entry_index = len(entry_offset)
        entry_offset.append(offset)
        first_character_ordinal = data[offset]
        possible_references = entries_with_first_character.get(first_character_ordinal, [])
        if not possible_references:
            entries_with_first_character[first_character_ordinal] = possible_references
        is_reference = False
        # _ because the entry length was only needed for sorting to prioritize
        # longer references
        for _, reference_index in possible_references:
            reference_offset = entry_offset[reference_index]
            # The referenced entry and the first character of the next entry
            entry_length = entry_offset[reference_index + 1] - reference_offset + 1
            if data[offset:offset + entry_length] == data[reference_offset:reference_offset + entry_length]:
                # Because we're looping largest to smallest, and due to the nature
                # of the compression, there's not any concievable back reference
                # that could be better... there's only other choices with equivalent
                # results.  We prefer the earliest index of any given length due to
                # it being potentially being representable in less digits.
                entries.append(f"_{reference_index}")
                is_reference = True
                break
        if not is_reference:
            entry_length = 1
            entries.append(str(first_character_ordinal))  # Add the ordinal, not the value
        offset += entry_length
        # Add this entry to the list of entries starting with this
        # first character so other entries can find it to reference it.
        # NOTE: Negated length so that longer entries are checked first.
        # Earlier indexes of the same length are also checked first.
        bisect.insort(possible_references, (-entry_length, entry_index))
    return ','.join(entries)