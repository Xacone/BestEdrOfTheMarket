rule definitly_not_trustable {
    strings:
        $pattern = "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00"

    condition:
        $pattern
}