import {Vocabulary, KeywordDefinition, Options} from "./types"
import SchemaObject from "./compile/schema_obj"
import Cache from "./cache"
import {ValidationError, MissingRefError} from "./compile/error_classes"
import rules from "./compile/rules"
import $dataMetaSchema from "./data"

var compileSchema = require("./compile"),
  resolve = require("./compile/resolve"),
  stableStringify = require("fast-json-stable-stringify")

import coreVocabulary from "./vocabularies/core"
import validationVocabulary from "./vocabularies/validation"
import applicatorVocabulary from "./vocabularies/applicator"
import formatVocabulary from "./vocabularies/format"
import {metadataVocabulary, contentVocabulary} from "./vocabularies/metadata"
import {addVocabulary, addKeyword, getKeyword, removeKeyword} from "./keyword"

module.exports = Ajv

Ajv.prototype.validate = validate
Ajv.prototype.compile = compile
Ajv.prototype.addSchema = addSchema
Ajv.prototype.addMetaSchema = addMetaSchema
Ajv.prototype.validateSchema = validateSchema
Ajv.prototype.getSchema = getSchema
Ajv.prototype.removeSchema = removeSchema
Ajv.prototype.addFormat = addFormat
Ajv.prototype.errorsText = errorsText
Ajv.prototype.addVocabulary = addVocabulary
Ajv.prototype.addKeyword = addKeyword
Ajv.prototype.getKeyword = getKeyword
Ajv.prototype.removeKeyword = removeKeyword

Ajv.prototype._addSchema = _addSchema
Ajv.prototype._compile = _compile

Ajv.prototype.compileAsync = require("./compile/async")
Ajv.prototype.$dataMetaSchema = $dataMetaSchema

Ajv.ValidationError = ValidationError
Ajv.MissingRefError = MissingRefError

var META_SCHEMA_ID = "http://json-schema.org/draft-07/schema"

var META_IGNORE_OPTIONS = ["removeAdditional", "useDefaults", "coerceTypes", "strictDefaults"]
const META_SUPPORT_DATA = ["/properties"]

/**
 * Creates validator instance.
 * Usage: `Ajv(opts)`
 * @param {Object} opts optional options
 * @return {Object} ajv instance
 */
export default function Ajv(opts: Options): void {
  if (!(this instanceof Ajv)) return new Ajv(opts)
  opts = this._opts = {...(opts || {})}
  setLogger(this)
  this._schemas = {}
  this._refs = {}
  this._fragments = {}
  this._formats = {}
  var formatOpt = opts.format
  opts.format = false

  this._cache = opts.cache || new Cache()
  this._loadingSchemas = {}
  this._compilations = []
  this.RULES = rules()
  checkDeprecatedOptions.call(this, opts)
  if (opts.serialize === undefined) opts.serialize = stableStringify
  this._metaOpts = getMetaSchemaOptions(this)

  if (opts.formats) addInitialFormats(this)
  this.addVocabulary(["$async"])
  this.addVocabulary(coreVocabulary)
  this.addVocabulary(validationVocabulary)
  this.addVocabulary(applicatorVocabulary)
  this.addVocabulary(formatVocabulary)
  this.addVocabulary(metadataVocabulary)
  this.addVocabulary(contentVocabulary)
  if (opts.keywords) addInitialKeywords(this, opts.keywords)
  addDefaultMetaSchema(this)
  if (typeof opts.meta == "object") this.addMetaSchema(opts.meta)
  addInitialSchemas(this)
  opts.format = formatOpt
}

function checkDeprecatedOptions(this, opts: Options) {
  if (opts.errorDataPath !== undefined) this.logger.error("NOT SUPPORTED: option errorDataPath")
  if (opts.schemaId !== undefined) this.logger.error("NOT SUPPORTED: option schemaId")
  if (opts.uniqueItems !== undefined) this.logger.error("NOT SUPPORTED: option uniqueItems")
  if (opts.jsPropertySyntax !== undefined) this.logger.warn("DEPRECATED: option jsPropertySyntax")
  if (opts.unicode !== undefined) this.logger.warn("DEPRECATED: option unicode")
}

/**
 * Validate data using schema
 * Schema will be compiled and cached (using serialized JSON as key. [fast-json-stable-stringify](https://github.com/epoberezkin/fast-json-stable-stringify) is used to serialize.
 * @this   Ajv
 * @param  {String|Object} schemaKeyRef key, ref or schema object
 * @param  {Any} data to be validated
 * @return {Boolean} validation result. Errors from the last validation will be available in `ajv.errors` (and also in compiled schema: `schema.errors`).
 */
function validate(schemaKeyRef, data) {
  var v
  if (typeof schemaKeyRef == "string") {
    v = this.getSchema(schemaKeyRef)
    if (!v) throw new Error('no schema with key or ref "' + schemaKeyRef + '"')
  } else {
    var schemaObj = this._addSchema(schemaKeyRef)
    v = schemaObj.validate || this._compile(schemaObj)
  }

  var valid = v(data)
  if (v.$async !== true) this.errors = v.errors
  return valid
}

/**
 * Create validating function for passed schema.
 * @this   Ajv
 * @param  {Object} schema schema object
 * @param  {Boolean} _meta true if schema is a meta-schema.
 * @return {Function} validating function
 */
function compile(schema, _meta) {
  var schemaObj = this._addSchema(schema, undefined, _meta)
  return schemaObj.validate || this._compile(schemaObj)
}

/**
 * Adds schema to the instance.
 * @this   Ajv
 * @param {Object|Array} schema schema or array of schemas. If array is passed, `key` and other parameters will be ignored.
 * @param {String} key Optional schema key. Can be passed to `validate` method instead of schema object or id/ref. One schema per instance can have empty `id` and `key`.
 * @param {Boolean} _skipValidation true to skip schema validation. Used internally, option validateSchema should be used instead.
 * @param {Boolean} _meta true if schema is a meta-schema. Used internally, addMetaSchema should be used instead.
 * @return {Ajv} this for method chaining
 */
function addSchema(schema, key, _skipValidation, _meta) {
  if (Array.isArray(schema)) {
    for (var i = 0; i < schema.length; i++) {
      this.addSchema(schema[i], undefined, _skipValidation, _meta)
    }
    return this
  }
  var id = schema.$id
  if (id !== undefined && typeof id != "string") {
    throw new Error("schema id must be string")
  }
  key = resolve.normalizeId(key || id)
  checkUnique(this, key)
  this._schemas[key] = this._addSchema(schema, _skipValidation, _meta, true)
  return this
}

/**
 * Add schema that will be used to validate other schemas
 * options in META_IGNORE_OPTIONS are alway set to false
 * @this   Ajv
 * @param {Object} schema schema object
 * @param {String} key optional schema key
 * @param {Boolean} skipValidation true to skip schema validation, can be used to override validateSchema option for meta-schema
 * @return {Ajv} this for method chaining
 */
function addMetaSchema(schema, key, skipValidation) {
  this.addSchema(schema, key, skipValidation, true)
  return this
}

/**
 * Validate schema
 * @this   Ajv
 * @param {Object} schema schema to validate
 * @param {Boolean} throwOrLogError pass true to throw (or log) an error if invalid
 * @return {Boolean} true if schema is valid
 */
function validateSchema(schema, throwOrLogError) {
  var $schema = schema.$schema
  if ($schema !== undefined && typeof $schema != "string") {
    throw new Error("$schema must be a string")
  }
  $schema = $schema || this._opts.defaultMeta || defaultMeta(this)
  if (!$schema) {
    this.logger.warn("meta-schema not available")
    this.errors = null
    return true
  }
  var valid = this.validate($schema, schema)
  if (!valid && throwOrLogError) {
    var message = "schema is invalid: " + this.errorsText()
    if (this._opts.validateSchema === "log") this.logger.error(message)
    else throw new Error(message)
  }
  return valid
}

function defaultMeta(self) {
  var meta = self._opts.meta
  self._opts.defaultMeta =
    typeof meta == "object"
      ? meta.$id || meta
      : self.getSchema(META_SCHEMA_ID)
      ? META_SCHEMA_ID
      : undefined
  return self._opts.defaultMeta
}

/**
 * Get compiled schema from the instance by `key` or `ref`.
 * @this   Ajv
 * @param  {String} keyRef `key` that was passed to `addSchema` or full schema reference (`schema.id` or resolved id).
 * @return {Function} schema validating function (with property `schema`).
 */
function getSchema(keyRef) {
  var schemaObj = _getSchemaObj(this, keyRef)
  switch (typeof schemaObj) {
    case "object":
      return schemaObj.validate || this._compile(schemaObj)
    case "string":
      return this.getSchema(schemaObj)
    case "undefined":
      return _getSchemaFragment(this, keyRef)
  }
}

function _getSchemaFragment(self, ref) {
  var res = resolve.schema.call(self, {schema: {}}, ref)
  if (res) {
    var schema = res.schema,
      root = res.root,
      baseId = res.baseId
    var v = compileSchema.call(self, schema, root, undefined, baseId)
    self._fragments[ref] = new SchemaObject({
      ref: ref,
      fragment: true,
      schema: schema,
      root: root,
      baseId: baseId,
      validate: v,
    })
    return v
  }
}

function _getSchemaObj(self, keyRef) {
  keyRef = resolve.normalizeId(keyRef)
  return self._schemas[keyRef] || self._refs[keyRef] || self._fragments[keyRef]
}

/**
 * Remove cached schema(s).
 * If no parameter is passed all schemas but meta-schemas are removed.
 * If RegExp is passed all schemas with key/id matching pattern but meta-schemas are removed.
 * Even if schema is referenced by other schemas it still can be removed as other schemas have local references.
 * @this   Ajv
 * @param  {String|Object|RegExp} schemaKeyRef key, ref, pattern to match key/ref or schema object
 * @return {Ajv} this for method chaining
 */
function removeSchema(schemaKeyRef) {
  if (schemaKeyRef instanceof RegExp) {
    _removeAllSchemas(this, this._schemas, schemaKeyRef)
    _removeAllSchemas(this, this._refs, schemaKeyRef)
    return this
  }
  switch (typeof schemaKeyRef) {
    case "undefined":
      _removeAllSchemas(this, this._schemas)
      _removeAllSchemas(this, this._refs)
      this._cache.clear()
      return this
    case "string":
      var schemaObj = _getSchemaObj(this, schemaKeyRef)
      if (schemaObj) this._cache.del(schemaObj.cacheKey)
      delete this._schemas[schemaKeyRef]
      delete this._refs[schemaKeyRef]
      return this
    case "object":
      var serialize = this._opts.serialize
      var cacheKey = serialize ? serialize(schemaKeyRef) : schemaKeyRef
      this._cache.del(cacheKey)
      var id = schemaKeyRef.$id
      if (id) {
        id = resolve.normalizeId(id)
        delete this._schemas[id]
        delete this._refs[id]
      }
  }
  return this
}

function _removeAllSchemas(self, schemas, regex?: RegExp) {
  for (var keyRef in schemas) {
    var schemaObj = schemas[keyRef]
    if (!schemaObj.meta && (!regex || regex.test(keyRef))) {
      self._cache.del(schemaObj.cacheKey)
      delete schemas[keyRef]
    }
  }
}

/* @this   Ajv */
function _addSchema(schema: {[x: string]: any} | boolean, skipValidation, meta, shouldAddSchema) {
  if (typeof schema != "object" && typeof schema != "boolean") {
    throw new Error("schema should be object or boolean")
  }
  var serialize = this._opts.serialize
  var cacheKey = serialize ? serialize(schema) : schema
  var cached = this._cache.get(cacheKey)
  if (cached) return cached

  shouldAddSchema = shouldAddSchema || this._opts.addUsedSchema !== false

  let $id, $schema
  if (typeof schema == "object") {
    $id = schema.$id
    $schema = schema.$schema
  }
  var id = resolve.normalizeId($id)
  if (id && shouldAddSchema) checkUnique(this, id)

  var willValidate = this._opts.validateSchema !== false && !skipValidation
  var recursiveMeta
  if (willValidate && !(recursiveMeta = id && id === resolve.normalizeId($schema))) {
    this.validateSchema(schema, true)
  }

  var localRefs = resolve.ids.call(this, schema)

  var schemaObj = new SchemaObject({id, schema, localRefs, cacheKey, meta})

  if (id[0] !== "#" && shouldAddSchema) this._refs[id] = schemaObj
  this._cache.put(cacheKey, schemaObj)

  if (willValidate && recursiveMeta) this.validateSchema(schema, true)

  return schemaObj
}

/* @this   Ajv */
function _compile(schemaObj, root) {
  if (schemaObj.compiling) return _makeValidate(schemaObj, root)
  schemaObj.compiling = true
  const v = _tryCompile.call(this, schemaObj, root)
  schemaObj.validate = v
  schemaObj.refs = v.refs
  schemaObj.refVal = v.refVal
  schemaObj.root = v.root
  return v
}

/* @this   Ajv */
function _tryCompile(schemaObj, root) {
  var currentOpts
  if (schemaObj.meta) {
    currentOpts = this._opts
    this._opts = this._metaOpts
  }

  try {
    return compileSchema.call(this, schemaObj.schema, root, schemaObj.localRefs)
  } catch (e) {
    delete schemaObj.validate
    throw e
  } finally {
    schemaObj.compiling = false
    if (schemaObj.meta) this._opts = currentOpts
  }
}

function _makeValidate(schemaObj, root) {
  schemaObj.validate = callValidate
  callValidate.schema = schemaObj.schema
  callValidate.errors = null
  callValidate.root = root ? root : callValidate
  if (schemaObj.schema.$async === true) callValidate.$async = true
  return callValidate

  /* @this   {*} - custom context, see passContext option */
  function callValidate(...args) {
    /* jshint validthis: true */
    var _validate = schemaObj.validate
    var result = _validate.apply(this, args)
    callValidate.errors = _validate.errors
    return result
  }
}

/**
 * Convert array of error message objects to string
 * @this   Ajv
 * @param  {Array<Object>} errors optional array of validation errors, if not passed errors from the instance are used.
 * @param  {Object} options optional options with properties `separator` and `dataVar`.
 * @return {String} human readable string with all errors descriptions
 */
function errorsText(errors, options) {
  errors = errors || this.errors
  if (!errors) return "No errors"
  options = options || {}
  var separator = options.separator === undefined ? ", " : options.separator
  var dataVar = options.dataVar === undefined ? "data" : options.dataVar

  var text = ""
  for (var i = 0; i < errors.length; i++) {
    var e = errors[i]
    if (e) text += dataVar + e.dataPath + " " + e.message + separator
  }
  return text.slice(0, -separator.length)
}

/**
 * Add format
 * @this   Ajv
 * @param {String} name format name
 * @param {String|RegExp|Function} format string is converted to RegExp; function should return boolean (true when valid)
 * @return {Ajv} this for method chaining
 */
function addFormat(name, format) {
  if (typeof format == "string") format = new RegExp(format)
  this._formats[name] = format
  return this
}

function addDefaultMetaSchema(self) {
  var $dataSchema
  if (self._opts.$data) {
    $dataSchema = require("./refs/data.json")
    self.addMetaSchema($dataSchema, $dataSchema.$id, true)
  }
  if (self._opts.meta === false) return
  var metaSchema = require("./refs/json-schema-draft-07.json")
  if (self._opts.$data) {
    metaSchema = self.$dataMetaSchema(metaSchema, META_SUPPORT_DATA)
  }
  self.addMetaSchema(metaSchema, META_SCHEMA_ID, true)
  self._refs["http://json-schema.org/schema"] = META_SCHEMA_ID
}

function addInitialSchemas(self) {
  var optsSchemas = self._opts.schemas
  if (!optsSchemas) return
  if (Array.isArray(optsSchemas)) self.addSchema(optsSchemas)
  else for (var key in optsSchemas) self.addSchema(optsSchemas[key], key)
}

function addInitialFormats(self) {
  for (var name in self._opts.formats) {
    var format = self._opts.formats[name]
    self.addFormat(name, format)
  }
}

function addInitialKeywords(self, defs: Vocabulary | {[x: string]: KeywordDefinition}) {
  if (Array.isArray(defs)) {
    self.addVocabulary(defs)
    return
  }
  self.logger.warn("keywords option as map is deprecated, pass array")
  for (var keyword in defs) {
    var def = defs[name]
    if (!def.keyword) def.keyword = keyword
    self.addKeyword(def)
  }
}

function checkUnique(self, id) {
  if (self._schemas[id] || self._refs[id]) {
    throw new Error('schema with key or id "' + id + '" already exists')
  }
}

function getMetaSchemaOptions(self) {
  var metaOpts = {...self._opts}
  for (var i = 0; i < META_IGNORE_OPTIONS.length; i++) {
    delete metaOpts[META_IGNORE_OPTIONS[i]]
  }
  return metaOpts
}

const noLogs = {log() {}, warn() {}, error() {}}

function setLogger(self) {
  var logger = self._opts.logger
  if (logger === false) {
    self.logger = noLogs
  } else {
    if (logger === undefined) logger = console
    if (!(typeof logger == "object" && logger.log && logger.warn && logger.error)) {
      throw new Error("logger must implement log, warn and error methods")
    }
    self.logger = logger
  }
}
