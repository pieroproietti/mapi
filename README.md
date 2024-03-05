# metadefender-core 

[metadefender-code.json]() è la definizione aggiornata delle API di metadefender-core, presa dal [sito di riferimento](https://docs.opswat.com/mdcore/metadefender-core), al link [OAS3](https://docs.opswat.com/mdcore/metadefender-core) in alto a destra, contrassegnato con "version": "v5.8.0".

La versione [metadefender-core-openapi3](https://github.com/OPSWAT/metadefender-core-openapi3) su github. è invece precedente version: v4.18.0 Non ci resta che fare riferimento esclusivamente a questa.


# Generazione dei modelli
Trattandosi di openapi3 sono riuscito a trovare un generatore di [modelli](https://github.com/koxudaxi/datamodel-code-generator)

 
```
datamodel-codegen --input metadefender-core.json --output model.py --output-model-type typing.TypedDict
```

--output-model-type {   pydantic.BaseModel,
                        pydantic_v2.BaseModel,
                        dataclasses.dataclass,
                        typing.TypedDict,
                        msgspec.Struct}


# API.py

Bisognerebbe far confluire questi modelli nella mia precedente api.py



