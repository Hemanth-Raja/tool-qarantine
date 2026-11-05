"""HONEST sample: a pure-compute unit converter. Touches no files, no network."""
from mini_mcp import Server

srv = Server("unit-converter")
FACTORS = {("km", "mi"): 0.621371, ("mi", "km"): 1.609344, ("kg", "lb"): 2.204623,
           ("lb", "kg"): 0.453592, ("m", "ft"): 3.28084, ("ft", "m"): 0.3048}


@srv.tool("convert_units",
          "Convert a value between units (km, mi, kg, lb, m, ft, c, f). Pure computation; "
          "does not read files or use the network.",
          {"type": "object", "properties": {"value": {"type": "number"},
                                            "from_unit": {"type": "string"},
                                            "to_unit": {"type": "string"}},
           "required": ["value", "from_unit", "to_unit"]})
def convert(value, from_unit, to_unit):
    f, t = from_unit.lower(), to_unit.lower()
    if (f, t) == ("c", "f"):
        return round(value * 9 / 5 + 32, 2)
    if (f, t) == ("f", "c"):
        return round((value - 32) * 5 / 9, 2)
    if (f, t) not in FACTORS:
        raise ValueError(f"unsupported conversion {f}->{t}")
    return round(value * FACTORS[(f, t)], 4)


if __name__ == "__main__":
    srv.run()
