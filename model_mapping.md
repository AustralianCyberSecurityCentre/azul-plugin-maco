This explains how to create an extractor that goes beyond what the
ExtractorModel allows.

Unless mentioned otherwise, these properties can be added to both
the `ExtractorModel.other` dictionary and the `ExtractorModel.Binary.other` dictionary.

Remember - If you don't map as much as you can to the regular ExtractorModel fields,
it is difficult for partners to use the information you generate.

## Compatibility

For the Azul extractor plugin to identify the `other` dictionary has valid content
for further processing, you must always set a `version` property as follows.

```json
"other": {"version": "azul_v1"}
```

If this version information is present, any unidentified properties will raise an error.

All `other` properties are optional.

## Features

The extractor model can't cover every Azul feature as it is primarily designed
to relay command-and-control / indicator-of-compromise information.

To set specific Azul features that the generic model doesn't map, do it like so:

```json
"other": {
    "version": "azul_v1",
    "features": {
        "myfeature1": [1,2,3],
        "myfeature2": ["apple","banana","carrot"],
        "myfeature3": [{
            "value": "block_thing",
            "offset": 0x49f,
            "size": 28,
            "label": "special unknown block"}],
        }
}
```

New feature names must be defined in the azul-plugin-maco,
otherwise your extractor will raise exceptions instead of running properly.

Note that the dictionary with keys maps to the Azul Runner `FeatureValue` class, so
only properties described there can be used as keys.

## Text Reports

Sometimes extractors will generate some useful information that doesn't map to any config but is useful to display.

This will be added to Azul as a text stream and displayed in the UI.

```json
"other": {
    "version": "azul_v1",
    "report": "an extended report\n with some newline characters,\n etc"
}
```

## Beyond Children

This technique only works within the `ExtractorModel.binaries.other` list.

Sometimes you may have an extractor that finds a complex hierarchy of binaries.

Within the list, a parent binary must precede a child.

```json
"other": {
    "version": "azul_v1",
    # only if the parent is not the original binary the extractor was run on.
    "child_of": "sha256 of parent binary"
}
```

## After adding new mapped features

If you add a new feature to the mapping, then it is recommend you track them in your extractors repo for testing purposes.

You might prefer to commit a environment file which you `source` at runtime. For example:

env.features:

```bash
export PLUGIN_CUSTOM_FEATURES='{"cool_cats": "meow|string"}'
```

And then:

```bash
source env.features
azul-plugin-maco -c scripts path/to/maco/extractors malware.file
```

Your extractors will fail if this is not defined.
