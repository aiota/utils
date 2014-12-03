// AIoTA Utility Functions
var crypto = require("crypto");
var uuid = require("node-uuid");
var jsonValidate = require("jsonschema").validate;

var bodySchemas = {
	"system":		{
						"register":		{
											type: "object",
											properties: {
												name: { type: "string", required: true },
												product: { type: "string", required: true }
											}
										},
									
						"session":		{
											type: "object",
											properties: {
												timeout: { type: "integer", minimum: 0, required: true }
											}
										},
									
						"unregister":	{
											type: "object"
										},
									
						"verify":		{
											type: "object",
											properties: {
												requestId: { type: "string", required: true },
												verificationCode: {
													type: "array",
													items: { type: "integer", minimum: 0 },
													minItems: 2,
													maxItems: 2,
													required: true
												},
											}
										}
					},
				
	"device":		{
						"telemetry":	{
											type: "object",
										}
					},
				
	"longpolling":	{
						"poll":			{
											type: "object",
											properties: {
												timeout: { type: "integer", minimum: 0, required: true }
											}
										}
					},
					
	"response":		{
						"ack":			{
											type: "object",
											properties: {
												requestId: { type: "string", required: true },
												progress: { type: "integer", default: 0, minimum: 0, maximum: 100 }
											}
										},
										
						"nack":			{
											type: "object",
											properties: {
												requestId: { type: "string", required: true },
												reason: { type: "string", default: "" },
											}
										},
					}
};

function getClassGroupTypeEnum(group)
{
	var typeEnum = [];
	
	switch (group) {
	case "system":			typeEnum.push("register");
							typeEnum.push("session");
							typeEnum.push("unregister");
							typeEnum.push("verify");
							break;
	case "device":			typeEnum.push("telemetry");
							break;
	case "longpolling":		typeEnum.push("poll");
							break;
	case "response":		typeEnum.push("ack");
							typeEnum.push("nack");
							break;
	}
	
	return typeEnum;
}

function validateJSONSchema(instance, schema)
{
	var v = jsonValidate(instance, schema);

	if (v.errors.length == 0) {
		for (var prop in schema.properties) {
		   if (!schema.properties[prop].required && schema.properties[prop].hasOwnProperty("default") && !instance.hasOwnProperty(prop)) {
			   instance[prop] = schema.properties[prop]["default"];
		   }
		}

		return { isValid: true };
	}
	else {
		return { isValid: false, error: v.errors };
	}
}

function getApplication(db, payload, callback)
{
	// Get the application associated with the token card uuid in the header
	db.collection("applications", function(err, collection) {
		if (err) {
			callback(200001, err);
			return;
		}

		collection.findOne({ "_id": payload.header.tokens.tokencardId }, { tokens: 1 }, function(err, app) {
			if (err) {
				callback(200002, err);
				return;
			}
			
			if (app == null) {
				callback(100004, "The header.tokens.tokencardId parameter in the request does not exist.");
				return;
			}
			else {
				var schema = {
					type: "object",
					properties: {
						_id: { type: "string", required: true },
						tokens: { 
							type: "array",
							items: { type: "string" },
							minItems: 1
						},
						required: true
					}
				};
						
				var v = validateJSONSchema(app, schema);
				
				if (v.isValid) {
					var numTokens = app["tokens"].length;
					
					if (payload.header.tokens.keyIndex >= numTokens) {
						callback(100005, "The header.tokens.keyIndex parameter is invalid.");
					}
					else if (payload.header.tokens.ivIndex >= numTokens) {
						callback(100006, "The header.tokens.ivIndex parameter is invalid.");
					}
					else {
						callback(0, app);
					}
				}
				else {
					callback(100003, "The application is not properly defined.");
				}
			}
		});
	});
}

function constructIV(public, private)
{
	var ivPrivate = private.substring(0, 4);
	var ivPublic = (public % 4294967296).toString(16);
	
	while (ivPublic.length < 8) {
		ivPublic = "0" + ivPublic;
	}
	
	return new Buffer(ivPublic + ivPrivate);
}

function encrypt(header, body, key, i, nonce, callback)
{
	var iv = constructIV(nonce, i);

	try {
		var aad = new Buffer(JSON.stringify(header));
	}
	catch(err) {
		callback(100007, err);
		return;
	}
	
	try {
		var payload = JSON.stringify(body);
	}
	catch(err) {
		callback(100007, err);
		return;
	}

	try {
		var cipher = crypto.createCipheriv("aes-256-gcm", new Buffer(key), iv);
		cipher.setAAD(aad);
		var encrypted = cipher.update(payload, "utf8", "hex");
		encrypted += cipher.final("hex");
		var tag = cipher.getAuthTag().toString("hex");
	}
	catch(err) {
		callback(100027, err);
		return;
	}
	
	callback(0, { ciphertext: encrypted, tag: tag });
}

function decrypt(payload, app, callback)
{
	switch (payload.header.encryption.method) {
	case "hmac-sha-256":	decryptHMACSHA256(payload, app, function(err, dec) {
								callback(err, dec);
							});
							break;
	case "aes-256-gcm":		decryptAES256GCM(payload, app, function(err, dec) {
								callback(err, dec);
							});
							break;
	}
}

function decryptHMACSHA256(payload, app, callback)
{
	callback(0, payload.body);
}

function decryptAES256GCM(payload, app, callback)
{
	var iv = constructIV(payload.header.tokens.nonce, app.tokens[payload.header.tokens.ivIndex]);

	try {
		var aad = new Buffer(JSON.stringify(payload.header));
	}
	catch(err) {
		callback(100007, err);
		return;
	}
	
	try {
		var decipher = crypto.createDecipheriv("aes-256-gcm", new Buffer(app.tokens[payload.header.tokens.keyIndex]), iv);
		decipher.setAAD(aad);
		decipher.setAuthTag(new Buffer(payload.icv, "hex"));
		var dec = decipher.update(payload.body, "hex", "utf8");
		dec += decipher.final("utf8");
	}
	catch(err) {
		callback(100008, err);
		return;
	}

	try {
		var bodyObj = JSON.parse(dec);
	}
	catch(err) {
		callback(100009, err);
		return;
	}
	
	callback(0, bodyObj);
}

function validateBody(db, payload, obj, callback)
{
	if (bodySchemas.hasOwnProperty(payload.header.class.group)) {
		if (bodySchemas[payload.header.class.group].hasOwnProperty(payload.header.class.type)) {		
			var v = validateJSONSchema(obj, bodySchemas[payload.header.class.group][payload.header.class.type]);
			
			if (v.isValid) {
				var now = Date.now();
				
				var success = { header: { requestId: payload.header.requestId, deviceId: payload.header.deviceId, type: payload.header.class.type, timestamp: now, ttl: payload.header.ttl, tokencardId: payload.header.tokens.tokencardId }, body: obj };
		
				// Check if the device exists
				db.collection("devices", function(err, collection) {
					if (err) {
						callback(true, err);
						return;
					}
			
					collection.findOne({ _id: payload.header.deviceId }, { _id: 0, apps: 1 }, function(err, device) {
						if (err) {
							callback(true, err);
							return;
						}
						
						if (device == null) {
							// The device does not exist
							if ((payload.header.class.group == "system") && (payload.header.class.type == "register")) {
								callback(0, success);
							}
							else {
								callback(100011, "The device does not not exist. Please register the application first.");
							}
							return;
						}
						else {
							var schema = {
								type: "object",
								properties: {
									apps: { 
										type: "object",
										required: true
									},
									required: true
								}
							};
									
							var v = validateJSONSchema(device, schema);
							
							if (v.isValid) {
								if (device.apps.hasOwnProperty(payload.header.tokens.tokencardId)) {
									// The application has been registered on this device
									if ((payload.header.class.group == "system") && (payload.header.class.type == "register")) {
										callback(100021, "The application has already been registered on this device.");
									}
									else if ((payload.header.class.group == "system") && (payload.header.class.type == "unregister")) {
										callback(0, success);
									}
									else if ((payload.header.class.group == "system") && (payload.header.class.type == "verify")) {
										if (device.apps[payload.header.tokens.tokencardId].status == "pending") {
											callback(0, success);
										}
										else {
											callback(100029, "The application registration is not pending on this device.");
										}
									}
									else {
										var set = {};
										set["apps." + payload.header.tokens.tokencardId + ".lastRequest"] = Date.now();
										
										collection.update({ _id: payload.header.deviceId }, { $set: set }, function(err, result) {
											if (err) {
												callback(200004, err);
												return;
											}
											
											if (device.apps[payload.header.tokens.tokencardId].status == "registered") {
												if (payload.header.class.group == "device") {
													// Check if the session token is correct
													if (device.apps[payload.header.tokens.tokencardId].session.id == payload.header.sessionId) {
														if ((device.apps[payload.header.tokens.tokencardId].session.timeoutAt > 0) && (device.apps[payload.header.tokens.tokencardId].session.timeoutAt <= now)) {
															callback(100014, "The session has timed out.");
														}
														else {
															// Check the schema
															db.collection("schema_definitions", function(err, collection) {
																if (err) {
																	callback(200001, err);
																	return;
																}
														
																collection.findOne({ schemaId: payload.header.schema.id, version: payload.header.schema.version }, { _id: 0, storage: 1, updateDevice: 1, schema: 1 }, function(err, def) {
																	if (err) {
																		callback(200002, err);
																		return;
																	}
																	
																	var v = validateJSONSchema(obj.telemetry, def.schema);
																	
																	if (v.isValid) {																
																		success.storage = def.storage;
																		success["updateDevice"] = def.updateDevice;
																	
																		callback(0, success);
																	}
																	else {
																		callback(100003, "Device message body does not match schema definition.");
																	}
																});
															});
														}
													}
													else {
														callback(100015, "Invalid session id.");
													}
												}
												else {
													callback(0, success);
												}
											}
											else {
												if ((payload.header.class.group == "longpolling") || (payload.header.class.group == "response")) {
													callback(0, success);
												}
												else {
													callback(100013, "The application registration is pending on this device.");
												}
											}
										});
									}
								}
								else {
									// The application has not yet been registered on this device
									if ((payload.header.class.group == "system") && (payload.header.class.type == "register")) {
										callback(0, success);
									}
									else {
										callback(100012, "The application has not been registered on this device.");
									}
								}
							}
							else {
								callback(100003, "The device is not properly defined.");
							}
						}
					});
				});
			}
			else {
				callback(100003, v.error);
			}
		}
		else {
			callback(100022, "A payload schema for this message type does not exist. (" + payload.header.class.group + "/" + payload.header.class.type + ")");
		}
	}
	else {
		callback(100028, "This message group does not exist. (" + payload.header.class.group + ")");
	}
}

module.exports = {
	validate: function(db, payload, callback) {		
		var schema = { 
			type: "object",
			properties: {
				header: {
					type: "object",
					properties: {
						"requestId": { type: "string", required: true },
						"deviceId": { type: "string", required: true },
						class: {
							type: "object",
							properties: {
								group: { type: "string", required: true },
								type: { type: "string", required: true }
							},
							required: true
						},
						ttl: { type: "integer", minimum: 0, maximum: 86400, required: true },
						encryption: {
							type: "object",
							properties: {
								method: { type: "string", enum: [ "none", "hmac-sha-256", "aes-256-gcm" ], required: true },
								tokencardId: { type: "string" },
								keyIndex: { type: "integer", minimum: 0, maximum: 63 },
								ivIndex: { type: "integer", minimum: 0, maximum: 63 },
								nonce: { type: "integer", minimum: 0, maximum: 4294967296 }
							},
							required: true
						},
					},
					required: true
				},
			}
		};
				
		var v = validateJSONSchema(payload, schema);
		
		if (v.isValid) {
			schema.properties.header.properties.class.properties.type["enum"] = getClassGroupTypeEnum(payload.header.class.group);
			
			if (payload.header.class.group == "device") {
				schema.properties.header.properties["sessionId"] = { type: "string", required: true };
				schema.properties.header.properties["schema"] = { 
					type: "object",
					properties: {
						id: { type: "string", required: true },
						version: {
							type: "object",
							properties: {
								major: { type: "integer", required: true },
								minor: { type: "integer", required: true }
							},
							required: true
						}
					},
					required: true
				};
			}
			
			switch (payload.header.encryption.method) {
			case "none":			// No encryption
									schema.properties["body"] = { type: "object", required: true };
									break;
			case "hmac-sha-256":	// HMAC-SHA-256 signature
									schema.properties.header.properties.encryption.properties.tokenCardId["required"] = true;
									schema.properties.header.properties.encryption.properties.keyIndex["required"] = true;
									schema.properties.header.properties.encryption.properties.nonce["required"] = true;
									schema.properties["body"] = { type: "object", required: true };
									schema.properties["icv"] = { type: "string", required: true };
									break;
			case "aes-256-gcm":		// AES-256-GCM encryption
									schema.properties.header.properties.encryption.properties.tokenCardId["required"] = true;
									schema.properties.header.properties.encryption.properties.keyIndex["required"] = true;
									schema.properties.header.properties.encryption.properties.ivIndex["required"] = true;
									schema.properties.header.properties.encryption.properties.nonce["required"] = true;
									schema.properties["body"] = { type: "string", required: true };
									schema.properties["icv"] = { type: "string", required: true };
									break;
			}
					
			var reply = {};
		
			var v = validateJSONSchema(payload, schema);
			
			if (v.isValid) {
				if (payload.header.deviceId == "") {
					callback(true, { nack: payload.header["requestId"], reason: "The header.deviceId field may not be empty.", errorCode: 100010 });
					return;
				}
				
				if (payload.header.encryption.method == "none") {
					validateBody(db, payload, dec, function(err, result) {
						if (err > 0) {
							callback(true, { nack: payload.header["requestId"], reason: result, errorCode: err });
							return;
						}
					
						callback(false, { ack: payload.header["requestId"] }, result);
					});
				}
				else {
					// Get the application which sent the request 
					getApplication(db, payload, function(err, app) {
						if (err > 0) {
							callback(true, { nack: payload.header["requestId"], reason: app, errorCode: err });
							return;
						}
						
						decrypt(payload, app, function(err, dec) {
							if (err > 0) {
								callback(true, { nack: payload.header["requestId"], reason: dec, errorCode: err });
								return;
							}
							
							validateBody(db, payload, dec, function(err, result) {
								if (err > 0) {
									callback(true, { nack: payload.header["requestId"], reason: result, errorCode: err });
									return;
								}
							
								callback(false, { ack: payload.header["requestId"] }, result);
							});
						});
					});
				}
			}
			else {
				callback(true, { nack: payload.header["requestId"], reason: v.error, errorCode: 100003 });
			}
		}
		else {
			if (payload.hasOwnProperty("header")) {
				if (payload.header.hasOwnProperty("requestId")) {
					callback(true, { nack: payload.header["requestId"], reason: v.error, errorCode: 100003 });
				}
				else {
					callback(true, { error: "Message does not have a valid request id.", errorCode: 100002 });
				}
			}
			else {
				callback(true, { error: "Malformed message.", errorCode: 100001 });
			}
		}
	},
	
	respond: function(requestId, deviceId, respondClass, tokencardId, tokens, nonce, payload, callback) {
		var response = { 
			header: {
				requestId: (requestId ? requestId : uuid.v4()),
				deviceId: deviceId,
				class: respondClass,
				ttl: 0,
				tokens: {
					tokencardId: tokencardId,
					keyIndex: Math.floor(Math.random() * tokens.length),
					ivIndex: Math.floor(Math.random() * tokens.length),
					nonce: nonce,
				}
			}
		};
	
		encrypt(response.header, payload, tokens[response.header.tokens.keyIndex], tokens[response.header.tokens.ivIndex], response.header.tokens.nonce, function(err, enc) {
			if (err > 0) {
				callback({ error: enc, errorCode: err });
				return;
			}
			
			response.body = enc.ciphertext;
			response.icv = enc.tag;

			callback(response);
		});
	},
	
	getQueue: function(c) {
		switch (c.group) {
		case "device":			return "telemetry-queue";
		case "longpolling":		return "longpolling-queue";
		case "response":		return "response-queue";
		case "system":			switch (c.type) {
								case "register":	return "register-queue";
								case "session":		return "session-queue";
								case "unregister":	return "register-queue";
								case "verify":		return "register-queue";
								default:			return "";
								}							
		default:				return "";
		}
	}
}
