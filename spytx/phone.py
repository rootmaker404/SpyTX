from __future__ import annotations

import phonenumbers
from phonenumbers import carrier, geocoder, timezone


def inspect_phone(number: str, region: str | None = None) -> dict[str, object]:
    parsed = phonenumbers.parse(number, region)
    possible = phonenumbers.is_possible_number(parsed)
    valid = phonenumbers.is_valid_number(parsed)
    return {
        "input": number,
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(
            parsed,
            phonenumbers.PhoneNumberFormat.INTERNATIONAL,
        ),
        "country_code": parsed.country_code,
        "national_number": str(parsed.national_number),
        "region": phonenumbers.region_code_for_number(parsed),
        "possible": possible,
        "valid": valid,
        "carrier": carrier.name_for_number(parsed, "en") or None,
        "location": geocoder.description_for_number(parsed, "en") or None,
        "timezones": list(timezone.time_zones_for_number(parsed)),
        "scope": "safe public phone metadata only",
    }
