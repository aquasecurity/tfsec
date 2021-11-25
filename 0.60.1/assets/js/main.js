(function (global, factory) {
    typeof exports === "object" && typeof module !== "undefined" ? module.exports = factory() : typeof define === "function" && define.amd ? define("uikit", factory) : (global = global || self,
        global.UIkit = factory());
})(this, function () {
    "use strict";
    function bind(fn, context) {
        return function (a) {
            var l = arguments.length;
            return l ? l > 1 ? fn.apply(context, arguments) : fn.call(context, a) : fn.call(context);
        };
    }
    var objPrototype = Object.prototype;
    var hasOwnProperty = objPrototype.hasOwnProperty;
    function hasOwn(obj, key) {
        return hasOwnProperty.call(obj, key);
    }
    var hyphenateCache = {};
    var hyphenateRe = /([a-z\d])([A-Z])/g;
    function hyphenate(str) {
        if (!(str in hyphenateCache)) {
            hyphenateCache[str] = str.replace(hyphenateRe, "$1-$2").toLowerCase();
        }
        return hyphenateCache[str];
    }
    var camelizeRe = /-(\w)/g;
    function camelize(str) {
        return str.replace(camelizeRe, toUpper);
    }
    function toUpper(_, c) {
        return c ? c.toUpperCase() : "";
    }
    function ucfirst(str) {
        return str.length ? toUpper(null, str.charAt(0)) + str.slice(1) : "";
    }
    var strPrototype = String.prototype;
    var startsWithFn = strPrototype.startsWith || function (search) {
        return this.lastIndexOf(search, 0) === 0;
    };
    function startsWith(str, search) {
        return startsWithFn.call(str, search);
    }
    var endsWithFn = strPrototype.endsWith || function (search) {
        return this.substr(-search.length) === search;
    };
    function endsWith(str, search) {
        return endsWithFn.call(str, search);
    }
    var includesFn = function (search) {
        return ~this.indexOf(search);
    };
    var includesStr = strPrototype.includes || includesFn;
    var includesArray = Array.prototype.includes || includesFn;
    function includes(obj, search) {
        return obj && (isString(obj) ? includesStr : includesArray).call(obj, search);
    }
    var isArray = Array.isArray;
    function isFunction(obj) {
        return typeof obj === "function";
    }
    function isObject(obj) {
        return obj !== null && typeof obj === "object";
    }
    function isPlainObject(obj) {
        return isObject(obj) && Object.getPrototypeOf(obj) === objPrototype;
    }
    function isWindow(obj) {
        return isObject(obj) && obj === obj.window;
    }
    function isDocument(obj) {
        return isObject(obj) && obj.nodeType === 9;
    }
    function isJQuery(obj) {
        return isObject(obj) && !!obj.jquery;
    }
    function isNode(obj) {
        return obj instanceof Node || isObject(obj) && obj.nodeType >= 1;
    }
    var toString = objPrototype.toString;
    function isNodeCollection(obj) {
        return toString.call(obj).match(/^\[object (NodeList|HTMLCollection)\]$/);
    }
    function isBoolean(value) {
        return typeof value === "boolean";
    }
    function isString(value) {
        return typeof value === "string";
    }
    function isNumber(value) {
        return typeof value === "number";
    }
    function isNumeric(value) {
        return isNumber(value) || isString(value) && !isNaN(value - parseFloat(value));
    }
    function isUndefined(value) {
        return value === void 0;
    }
    function toBoolean(value) {
        return isBoolean(value) ? value : value === "true" || value === "1" || value === "" ? true : value === "false" || value === "0" ? false : value;
    }
    function toNumber(value) {
        var number = Number(value);
        return !isNaN(number) ? number : false;
    }
    function toFloat(value) {
        return parseFloat(value) || 0;
    }
    function toNode(element) {
        return isNode(element) || isWindow(element) || isDocument(element) ? element : isNodeCollection(element) || isJQuery(element) ? element[0] : isArray(element) ? toNode(element[0]) : null;
    }
    var arrayProto = Array.prototype;
    function toNodes(element) {
        return isNode(element) ? [element] : isNodeCollection(element) ? arrayProto.slice.call(element) : isArray(element) ? element.map(toNode).filter(Boolean) : isJQuery(element) ? element.toArray() : [];
    }
    function toList(value) {
        return isArray(value) ? value : isString(value) ? value.split(/,(?![^(]*\))/).map(function (value) {
            return isNumeric(value) ? toNumber(value) : toBoolean(value.trim());
        }) : [value];
    }
    function toMs(time) {
        return !time ? 0 : endsWith(time, "ms") ? toFloat(time) : toFloat(time) * 1e3;
    }
    function isEqual(value, other) {
        return value === other || isObject(value) && isObject(other) && Object.keys(value).length === Object.keys(other).length && each(value, function (val, key) {
            return val === other[key];
        });
    }
    function swap(value, a, b) {
        return value.replace(new RegExp(a + "|" + b, "mg"), function (match) {
            return match === a ? b : a;
        });
    }
    var assign = Object.assign || function (target) {
        var args = [], len = arguments.length - 1;
        while (len-- > 0) args[len] = arguments[len + 1];
        target = Object(target);
        for (var i = 0; i < args.length; i++) {
            var source = args[i];
            if (source !== null) {
                for (var key in source) {
                    if (hasOwn(source, key)) {
                        target[key] = source[key];
                    }
                }
            }
        }
        return target;
    };
    function each(obj, cb) {
        for (var key in obj) {
            if (false === cb(obj[key], key)) {
                return false;
            }
        }
        return true;
    }
    function sortBy(collection, prop) {
        return collection.sort(function (ref, ref$1) {
            var propA = ref[prop];
            if (propA === void 0) propA = 0;
            var propB = ref$1[prop];
            if (propB === void 0) propB = 0;
            return propA > propB ? 1 : propB > propA ? -1 : 0;
        });
    }
    function clamp(number, min, max) {
        if (min === void 0) min = 0;
        if (max === void 0) max = 1;
        return Math.min(Math.max(toNumber(number) || 0, min), max);
    }
    function noop() { }
    function intersectRect(r1, r2) {
        return r1.left < r2.right && r1.right > r2.left && r1.top < r2.bottom && r1.bottom > r2.top;
    }
    function pointInRect(point, rect) {
        return point.x <= rect.right && point.x >= rect.left && point.y <= rect.bottom && point.y >= rect.top;
    }
    var Dimensions = {
        ratio: function (dimensions, prop, value) {
            var obj;
            var aProp = prop === "width" ? "height" : "width";
            return obj = {}, obj[aProp] = dimensions[prop] ? Math.round(value * dimensions[aProp] / dimensions[prop]) : dimensions[aProp],
                obj[prop] = value, obj;
        },
        contain: function (dimensions, maxDimensions) {
            var this$1 = this;
            dimensions = assign({}, dimensions);
            each(dimensions, function (_, prop) {
                return dimensions = dimensions[prop] > maxDimensions[prop] ? this$1.ratio(dimensions, prop, maxDimensions[prop]) : dimensions;
            });
            return dimensions;
        },
        cover: function (dimensions, maxDimensions) {
            var this$1 = this;
            dimensions = this.contain(dimensions, maxDimensions);
            each(dimensions, function (_, prop) {
                return dimensions = dimensions[prop] < maxDimensions[prop] ? this$1.ratio(dimensions, prop, maxDimensions[prop]) : dimensions;
            });
            return dimensions;
        }
    };
    function attr(element, name, value) {
        if (isObject(name)) {
            for (var key in name) {
                attr(element, key, name[key]);
            }
            return;
        }
        if (isUndefined(value)) {
            element = toNode(element);
            return element && element.getAttribute(name);
        } else {
            toNodes(element).forEach(function (element) {
                if (isFunction(value)) {
                    value = value.call(element, attr(element, name));
                }
                if (value === null) {
                    removeAttr(element, name);
                } else {
                    element.setAttribute(name, value);
                }
            });
        }
    }
    function hasAttr(element, name) {
        return toNodes(element).some(function (element) {
            return element.hasAttribute(name);
        });
    }
    function removeAttr(element, name) {
        element = toNodes(element);
        name.split(" ").forEach(function (name) {
            return element.forEach(function (element) {
                return element.removeAttribute(name);
            });
        });
    }
    function data(element, attribute) {
        for (var i = 0, attrs = [attribute, "data-" + attribute]; i < attrs.length; i++) {
            if (hasAttr(element, attrs[i])) {
                return attr(element, attrs[i]);
            }
        }
    }
    function query(selector, context) {
        return toNode(selector) || find(selector, getContext(selector, context));
    }
    function queryAll(selector, context) {
        var nodes = toNodes(selector);
        return nodes.length && nodes || findAll(selector, getContext(selector, context));
    }
    function getContext(selector, context) {
        if (context === void 0) context = document;
        return isContextSelector(selector) || isDocument(context) ? context : context.ownerDocument;
    }
    function find(selector, context) {
        return toNode(_query(selector, context, "querySelector"));
    }
    function findAll(selector, context) {
        return toNodes(_query(selector, context, "querySelectorAll"));
    }
    function _query(selector, context, queryFn) {
        if (context === void 0) context = document;
        if (!selector || !isString(selector)) {
            return null;
        }
        selector = selector.replace(contextSanitizeRe, "$1 *");
        var removes;
        if (isContextSelector(selector)) {
            removes = [];
            selector = selector.split(",").map(function (selector, i) {
                var ctx = context;
                selector = selector.trim();
                if (selector[0] === "!") {
                    var selectors = selector.substr(1).trim().split(" ");
                    ctx = closest(context.parentNode, selectors[0]);
                    selector = selectors.slice(1).join(" ").trim();
                }
                if (selector[0] === "-") {
                    var selectors$1 = selector.substr(1).trim().split(" ");
                    var prev = (ctx || context).previousElementSibling;
                    ctx = matches(prev, selector.substr(1)) ? prev : null;
                    selector = selectors$1.slice(1).join(" ");
                }
                if (!ctx) {
                    return null;
                }
                if (!ctx.id) {
                    ctx.id = "uk-" + Date.now() + i;
                    removes.push(function () {
                        return removeAttr(ctx, "id");
                    });
                }
                return "#" + escape(ctx.id) + " " + selector;
            }).filter(Boolean).join(",");
            context = document;
        }
        try {
            return context[queryFn](selector);
        } catch (e) {
            return null;
        } finally {
            removes && removes.forEach(function (remove) {
                return remove();
            });
        }
    }
    var contextSelectorRe = /(^|,)\s*[!>+~-]/;
    var contextSanitizeRe = /([!>+~-])(?=\s+[!>+~-]|\s*$)/g;
    function isContextSelector(selector) {
        return isString(selector) && selector.match(contextSelectorRe);
    }
    var elProto = Element.prototype;
    var matchesFn = elProto.matches || elProto.webkitMatchesSelector || elProto.msMatchesSelector;
    function matches(element, selector) {
        return toNodes(element).some(function (element) {
            return matchesFn.call(element, selector);
        });
    }
    var closestFn = elProto.closest || function (selector) {
        var ancestor = this;
        do {
            if (matches(ancestor, selector)) {
                return ancestor;
            }
            ancestor = ancestor.parentNode;
        } while (ancestor && ancestor.nodeType === 1);
    };
    function closest(element, selector) {
        if (startsWith(selector, ">")) {
            selector = selector.slice(1);
        }
        return isNode(element) ? element.parentNode && closestFn.call(element, selector) : toNodes(element).map(function (element) {
            return closest(element, selector);
        }).filter(Boolean);
    }
    function parents(element, selector) {
        var elements = [];
        var parent = toNode(element).parentNode;
        while (parent && parent.nodeType === 1) {
            if (matches(parent, selector)) {
                elements.push(parent);
            }
            parent = parent.parentNode;
        }
        return elements;
    }
    var escapeFn = window.CSS && CSS.escape || function (css) {
        return css.replace(/([^\x7f-\uFFFF\w-])/g, function (match) {
            return "\\" + match;
        });
    };
    function escape(css) {
        return isString(css) ? escapeFn.call(null, css) : "";
    }
    var voidElements = {
        area: true,
        base: true,
        br: true,
        col: true,
        embed: true,
        hr: true,
        img: true,
        input: true,
        keygen: true,
        link: true,
        menuitem: true,
        meta: true,
        param: true,
        source: true,
        track: true,
        wbr: true
    };
    function isVoidElement(element) {
        return toNodes(element).some(function (element) {
            return voidElements[element.tagName.toLowerCase()];
        });
    }
    function isVisible(element) {
        return toNodes(element).some(function (element) {
            return element.offsetWidth || element.offsetHeight || element.getClientRects().length;
        });
    }
    var selInput = "input,select,textarea,button";
    function isInput(element) {
        return toNodes(element).some(function (element) {
            return matches(element, selInput);
        });
    }
    function filter(element, selector) {
        return toNodes(element).filter(function (element) {
            return matches(element, selector);
        });
    }
    function within(element, selector) {
        return !isString(selector) ? element === selector || (isDocument(selector) ? selector.documentElement : toNode(selector)).contains(toNode(element)) : matches(element, selector) || closest(element, selector);
    }
    var isIE = /msie|trident/i.test(window.navigator.userAgent);
    var isRtl = attr(document.documentElement, "dir") === "rtl";
    var hasTouchEvents = "ontouchstart" in window;
    var hasPointerEvents = window.PointerEvent;
    var hasTouch = hasTouchEvents || window.DocumentTouch && document instanceof DocumentTouch || navigator.maxTouchPoints;
    var pointerDown = hasPointerEvents ? "pointerdown" : hasTouchEvents ? "touchstart" : "mousedown";
    var pointerMove = hasPointerEvents ? "pointermove" : hasTouchEvents ? "touchmove" : "mousemove";
    var pointerUp = hasPointerEvents ? "pointerup" : hasTouchEvents ? "touchend" : "mouseup";
    var pointerEnter = hasPointerEvents ? "pointerenter" : hasTouchEvents ? "" : "mouseenter";
    var pointerLeave = hasPointerEvents ? "pointerleave" : hasTouchEvents ? "" : "mouseleave";
    var pointerCancel = hasPointerEvents ? "pointercancel" : "touchcancel";
    function on() {
        var args = [], len = arguments.length;
        while (len--) args[len] = arguments[len];
        var ref = getArgs(args);
        var targets = ref[0];
        var type = ref[1];
        var selector = ref[2];
        var listener = ref[3];
        var useCapture = ref[4];
        targets = toEventTargets(targets);
        if (selector) {
            listener = delegate(targets, selector, listener);
        }
        if (listener.length > 1) {
            listener = detail(listener);
        }
        type.split(" ").forEach(function (type) {
            return targets.forEach(function (target) {
                return target.addEventListener(type, listener, useCapture);
            });
        });
        return function () {
            return off(targets, type, listener, useCapture);
        };
    }
    function off(targets, type, listener, useCapture) {
        if (useCapture === void 0) useCapture = false;
        targets = toEventTargets(targets);
        type.split(" ").forEach(function (type) {
            return targets.forEach(function (target) {
                return target.removeEventListener(type, listener, useCapture);
            });
        });
    }
    function once() {
        var args = [], len = arguments.length;
        while (len--) args[len] = arguments[len];
        var ref = getArgs(args);
        var element = ref[0];
        var type = ref[1];
        var selector = ref[2];
        var listener = ref[3];
        var useCapture = ref[4];
        var condition = ref[5];
        var off = on(element, type, selector, function (e) {
            var result = !condition || condition(e);
            if (result) {
                off();
                listener(e, result);
            }
        }, useCapture);
        return off;
    }
    function trigger(targets, event, detail) {
        return toEventTargets(targets).reduce(function (notCanceled, target) {
            return notCanceled && target.dispatchEvent(createEvent(event, true, true, detail));
        }, true);
    }
    function createEvent(e, bubbles, cancelable, detail) {
        if (bubbles === void 0) bubbles = true;
        if (cancelable === void 0) cancelable = false;
        if (isString(e)) {
            var event = document.createEvent("CustomEvent");
            event.initCustomEvent(e, bubbles, cancelable, detail);
            e = event;
        }
        return e;
    }
    function getArgs(args) {
        if (isFunction(args[2])) {
            args.splice(2, 0, false);
        }
        return args;
    }
    function delegate(delegates, selector, listener) {
        var this$1 = this;
        return function (e) {
            delegates.forEach(function (delegate) {
                var current = selector[0] === ">" ? findAll(selector, delegate).reverse().filter(function (element) {
                    return within(e.target, element);
                })[0] : closest(e.target, selector);
                if (current) {
                    e.delegate = delegate;
                    e.current = current;
                    listener.call(this$1, e);
                }
            });
        };
    }
    function detail(listener) {
        return function (e) {
            return isArray(e.detail) ? listener.apply(void 0, [e].concat(e.detail)) : listener(e);
        };
    }
    function isEventTarget(target) {
        return target && "addEventListener" in target;
    }
    function toEventTarget(target) {
        return isEventTarget(target) ? target : toNode(target);
    }
    function toEventTargets(target) {
        return isArray(target) ? target.map(toEventTarget).filter(Boolean) : isString(target) ? findAll(target) : isEventTarget(target) ? [target] : toNodes(target);
    }
    function preventClick() {
        var timer = setTimeout(once(document, "click", function (e) {
            e.preventDefault();
            e.stopImmediatePropagation();
            clearTimeout(timer);
        }, true));
        trigger(document, pointerCancel);
    }
    var Promise = "Promise" in window ? window.Promise : PromiseFn;
    var Deferred = function () {
        var this$1 = this;
        this.promise = new Promise(function (resolve, reject) {
            this$1.reject = reject;
            this$1.resolve = resolve;
        });
    };
    var RESOLVED = 0;
    var REJECTED = 1;
    var PENDING = 2;
    var async = "setImmediate" in window ? setImmediate : setTimeout;
    function PromiseFn(executor) {
        this.state = PENDING;
        this.value = undefined;
        this.deferred = [];
        var promise = this;
        try {
            executor(function (x) {
                promise.resolve(x);
            }, function (r) {
                promise.reject(r);
            });
        } catch (e) {
            promise.reject(e);
        }
    }
    PromiseFn.reject = function (r) {
        return new PromiseFn(function (resolve, reject) {
            reject(r);
        });
    };
    PromiseFn.resolve = function (x) {
        return new PromiseFn(function (resolve, reject) {
            resolve(x);
        });
    };
    PromiseFn.all = function all(iterable) {
        return new PromiseFn(function (resolve, reject) {
            var result = [];
            var count = 0;
            if (iterable.length === 0) {
                resolve(result);
            }
            function resolver(i) {
                return function (x) {
                    result[i] = x;
                    count += 1;
                    if (count === iterable.length) {
                        resolve(result);
                    }
                };
            }
            for (var i = 0; i < iterable.length; i += 1) {
                PromiseFn.resolve(iterable[i]).then(resolver(i), reject);
            }
        });
    };
    PromiseFn.race = function race(iterable) {
        return new PromiseFn(function (resolve, reject) {
            for (var i = 0; i < iterable.length; i += 1) {
                PromiseFn.resolve(iterable[i]).then(resolve, reject);
            }
        });
    };
    var p = PromiseFn.prototype;
    p.resolve = function resolve(x) {
        var promise = this;
        if (promise.state === PENDING) {
            if (x === promise) {
                throw new TypeError("Promise settled with itself.");
            }
            var called = false;
            try {
                var then = x && x.then;
                if (x !== null && isObject(x) && isFunction(then)) {
                    then.call(x, function (x) {
                        if (!called) {
                            promise.resolve(x);
                        }
                        called = true;
                    }, function (r) {
                        if (!called) {
                            promise.reject(r);
                        }
                        called = true;
                    });
                    return;
                }
            } catch (e) {
                if (!called) {
                    promise.reject(e);
                }
                return;
            }
            promise.state = RESOLVED;
            promise.value = x;
            promise.notify();
        }
    };
    p.reject = function reject(reason) {
        var promise = this;
        if (promise.state === PENDING) {
            if (reason === promise) {
                throw new TypeError("Promise settled with itself.");
            }
            promise.state = REJECTED;
            promise.value = reason;
            promise.notify();
        }
    };
    p.notify = function notify() {
        var this$1 = this;
        async(function () {
            if (this$1.state !== PENDING) {
                while (this$1.deferred.length) {
                    var ref = this$1.deferred.shift();
                    var onResolved = ref[0];
                    var onRejected = ref[1];
                    var resolve = ref[2];
                    var reject = ref[3];
                    try {
                        if (this$1.state === RESOLVED) {
                            if (isFunction(onResolved)) {
                                resolve(onResolved.call(undefined, this$1.value));
                            } else {
                                resolve(this$1.value);
                            }
                        } else if (this$1.state === REJECTED) {
                            if (isFunction(onRejected)) {
                                resolve(onRejected.call(undefined, this$1.value));
                            } else {
                                reject(this$1.value);
                            }
                        }
                    } catch (e) {
                        reject(e);
                    }
                }
            }
        });
    };
    p.then = function then(onResolved, onRejected) {
        var this$1 = this;
        return new PromiseFn(function (resolve, reject) {
            this$1.deferred.push([onResolved, onRejected, resolve, reject]);
            this$1.notify();
        });
    };
    p.catch = function (onRejected) {
        return this.then(undefined, onRejected);
    };
    function ajax(url, options) {
        return new Promise(function (resolve, reject) {
            var env = assign({
                data: null,
                method: "GET",
                headers: {},
                xhr: new XMLHttpRequest(),
                beforeSend: noop,
                responseType: ""
            }, options);
            env.beforeSend(env);
            var xhr = env.xhr;
            for (var prop in env) {
                if (prop in xhr) {
                    try {
                        xhr[prop] = env[prop];
                    } catch (e) { }
                }
            }
            xhr.open(env.method.toUpperCase(), url);
            for (var header in env.headers) {
                xhr.setRequestHeader(header, env.headers[header]);
            }
            on(xhr, "load", function () {
                if (xhr.status === 0 || xhr.status >= 200 && xhr.status < 300 || xhr.status === 304) {
                    resolve(xhr);
                } else {
                    reject(assign(Error(xhr.statusText), {
                        xhr: xhr,
                        status: xhr.status
                    }));
                }
            });
            on(xhr, "error", function () {
                return reject(assign(Error("Network Error"), {
                    xhr: xhr
                }));
            });
            on(xhr, "timeout", function () {
                return reject(assign(Error("Network Timeout"), {
                    xhr: xhr
                }));
            });
            xhr.send(env.data);
        });
    }
    function getImage(src, srcset, sizes) {
        return new Promise(function (resolve, reject) {
            var img = new Image();
            img.onerror = reject;
            img.onload = function () {
                return resolve(img);
            };
            sizes && (img.sizes = sizes);
            srcset && (img.srcset = srcset);
            img.src = src;
        });
    }
    function ready(fn) {
        if (document.readyState !== "loading") {
            fn();
            return;
        }
        var unbind = on(document, "DOMContentLoaded", function () {
            unbind();
            fn();
        });
    }
    function index(element, ref) {
        return ref ? toNodes(element).indexOf(toNode(ref)) : toNodes((element = toNode(element)) && element.parentNode.children).indexOf(element);
    }
    function getIndex(i, elements, current, finite) {
        if (current === void 0) current = 0;
        if (finite === void 0) finite = false;
        elements = toNodes(elements);
        var length = elements.length;
        i = isNumeric(i) ? toNumber(i) : i === "next" ? current + 1 : i === "previous" ? current - 1 : index(elements, i);
        if (finite) {
            return clamp(i, 0, length - 1);
        }
        i %= length;
        return i < 0 ? i + length : i;
    }
    function empty(element) {
        element = $(element);
        element.innerHTML = "";
        return element;
    }
    function html(parent, html) {
        parent = $(parent);
        return isUndefined(html) ? parent.innerHTML : append(parent.hasChildNodes() ? empty(parent) : parent, html);
    }
    function prepend(parent, element) {
        parent = $(parent);
        if (!parent.hasChildNodes()) {
            return append(parent, element);
        } else {
            return insertNodes(element, function (element) {
                return parent.insertBefore(element, parent.firstChild);
            });
        }
    }
    function append(parent, element) {
        parent = $(parent);
        return insertNodes(element, function (element) {
            return parent.appendChild(element);
        });
    }
    function before(ref, element) {
        ref = $(ref);
        return insertNodes(element, function (element) {
            return ref.parentNode.insertBefore(element, ref);
        });
    }
    function after(ref, element) {
        ref = $(ref);
        return insertNodes(element, function (element) {
            return ref.nextSibling ? before(ref.nextSibling, element) : append(ref.parentNode, element);
        });
    }
    function insertNodes(element, fn) {
        element = isString(element) ? fragment(element) : element;
        return element ? "length" in element ? toNodes(element).map(fn) : fn(element) : null;
    }
    function remove(element) {
        toNodes(element).map(function (element) {
            return element.parentNode && element.parentNode.removeChild(element);
        });
    }
    function wrapAll(element, structure) {
        structure = toNode(before(element, structure));
        while (structure.firstChild) {
            structure = structure.firstChild;
        }
        append(structure, element);
        return structure;
    }
    function wrapInner(element, structure) {
        return toNodes(toNodes(element).map(function (element) {
            return element.hasChildNodes ? wrapAll(toNodes(element.childNodes), structure) : append(element, structure);
        }));
    }
    function unwrap(element) {
        toNodes(element).map(function (element) {
            return element.parentNode;
        }).filter(function (value, index, self) {
            return self.indexOf(value) === index;
        }).forEach(function (parent) {
            before(parent, parent.childNodes);
            remove(parent);
        });
    }
    var fragmentRe = /^\s*<(\w+|!)[^>]*>/;
    var singleTagRe = /^<(\w+)\s*\/?>(?:<\/\1>)?$/;
    function fragment(html) {
        var matches$$1 = singleTagRe.exec(html);
        if (matches$$1) {
            return document.createElement(matches$$1[1]);
        }
        var container = document.createElement("div");
        if (fragmentRe.test(html)) {
            container.insertAdjacentHTML("beforeend", html.trim());
        } else {
            container.textContent = html;
        }
        return container.childNodes.length > 1 ? toNodes(container.childNodes) : container.firstChild;
    }
    function apply(node, fn) {
        if (!node || node.nodeType !== 1) {
            return;
        }
        fn(node);
        node = node.firstElementChild;
        while (node) {
            apply(node, fn);
            node = node.nextElementSibling;
        }
    }
    function $(selector, context) {
        return !isString(selector) ? toNode(selector) : isHtml(selector) ? toNode(fragment(selector)) : find(selector, context);
    }
    function $$(selector, context) {
        return !isString(selector) ? toNodes(selector) : isHtml(selector) ? toNodes(fragment(selector)) : findAll(selector, context);
    }
    function isHtml(str) {
        return str[0] === "<" || str.match(/^\s*</);
    }
    function addClass(element) {
        var args = [], len = arguments.length - 1;
        while (len-- > 0) args[len] = arguments[len + 1];
        apply$1(element, args, "add");
    }
    function removeClass(element) {
        var args = [], len = arguments.length - 1;
        while (len-- > 0) args[len] = arguments[len + 1];
        apply$1(element, args, "remove");
    }
    function removeClasses(element, cls) {
        attr(element, "class", function (value) {
            return (value || "").replace(new RegExp("\\b" + cls + "\\b", "g"), "");
        });
    }
    function replaceClass(element) {
        var args = [], len = arguments.length - 1;
        while (len-- > 0) args[len] = arguments[len + 1];
        args[0] && removeClass(element, args[0]);
        args[1] && addClass(element, args[1]);
    }
    function hasClass(element, cls) {
        return cls && toNodes(element).some(function (element) {
            return element.classList.contains(cls.split(" ")[0]);
        });
    }
    function toggleClass(element) {
        var args = [], len = arguments.length - 1;
        while (len-- > 0) args[len] = arguments[len + 1];
        if (!args.length) {
            return;
        }
        args = getArgs$1(args);
        var force = !isString(args[args.length - 1]) ? args.pop() : [];
        args = args.filter(Boolean);
        toNodes(element).forEach(function (ref) {
            var classList = ref.classList;
            for (var i = 0; i < args.length; i++) {
                supports.Force ? classList.toggle.apply(classList, [args[i]].concat(force)) : classList[(!isUndefined(force) ? force : !classList.contains(args[i])) ? "add" : "remove"](args[i]);
            }
        });
    }
    function apply$1(element, args, fn) {
        args = getArgs$1(args).filter(Boolean);
        args.length && toNodes(element).forEach(function (ref) {
            var classList = ref.classList;
            supports.Multiple ? classList[fn].apply(classList, args) : args.forEach(function (cls) {
                return classList[fn](cls);
            });
        });
    }
    function getArgs$1(args) {
        return args.reduce(function (args, arg) {
            return args.concat.call(args, isString(arg) && includes(arg, " ") ? arg.trim().split(" ") : arg);
        }, []);
    }
    var supports = {};
    (function () {
        var list = document.createElement("_").classList;
        if (list) {
            list.add("a", "b");
            list.toggle("c", false);
            supports.Multiple = list.contains("b");
            supports.Force = !list.contains("c");
        }
        list = null;
    })();
    var cssNumber = {
        "animation-iteration-count": true,
        "column-count": true,
        "fill-opacity": true,
        "flex-grow": true,
        "flex-shrink": true,
        "font-weight": true,
        "line-height": true,
        opacity: true,
        order: true,
        orphans: true,
        widows: true,
        "z-index": true,
        zoom: true
    };
    function css(element, property, value) {
        return toNodes(element).map(function (element) {
            if (isString(property)) {
                property = propName(property);
                if (isUndefined(value)) {
                    return getStyle(element, property);
                } else if (!value && !isNumber(value)) {
                    element.style.removeProperty(property);
                } else {
                    element.style[property] = isNumeric(value) && !cssNumber[property] ? value + "px" : value;
                }
            } else if (isArray(property)) {
                var styles = getStyles(element);
                return property.reduce(function (props, property) {
                    props[property] = styles[propName(property)];
                    return props;
                }, {});
            } else if (isObject(property)) {
                each(property, function (value, property) {
                    return css(element, property, value);
                });
            }
            return element;
        })[0];
    }
    function getStyles(element, pseudoElt) {
        element = toNode(element);
        return element.ownerDocument.defaultView.getComputedStyle(element, pseudoElt);
    }
    function getStyle(element, property, pseudoElt) {
        return getStyles(element, pseudoElt)[property];
    }
    var vars = {};
    function getCssVar(name) {
        var docEl = document.documentElement;
        if (!isIE) {
            return getStyles(docEl).getPropertyValue("--uk-" + name);
        }
        if (!(name in vars)) {
            var element = append(docEl, document.createElement("div"));
            addClass(element, "uk-" + name);
            vars[name] = getStyle(element, "content", ":before").replace(/^["'](.*)["']$/, "$1");
            remove(element);
        }
        return vars[name];
    }
    var cssProps = {};
    function propName(name) {
        var ret = cssProps[name];
        if (!ret) {
            ret = cssProps[name] = vendorPropName(name) || name;
        }
        return ret;
    }
    var cssPrefixes = ["webkit", "moz", "ms"];
    var ref = document.createElement("_");
    var style = ref.style;
    function vendorPropName(name) {
        name = hyphenate(name);
        if (name in style) {
            return name;
        }
        var i = cssPrefixes.length, prefixedName;
        while (i--) {
            prefixedName = "-" + cssPrefixes[i] + "-" + name;
            if (prefixedName in style) {
                return prefixedName;
            }
        }
    }
    function transition(element, props, duration, timing) {
        if (duration === void 0) duration = 400;
        if (timing === void 0) timing = "linear";
        return Promise.all(toNodes(element).map(function (element) {
            return new Promise(function (resolve, reject) {
                for (var name in props) {
                    var value = css(element, name);
                    if (value === "") {
                        css(element, name, value);
                    }
                }
                var timer = setTimeout(function () {
                    return trigger(element, "transitionend");
                }, duration);
                once(element, "transitionend transitioncanceled", function (ref) {
                    var type = ref.type;
                    clearTimeout(timer);
                    removeClass(element, "uk-transition");
                    css(element, {
                        "transition-property": "",
                        "transition-duration": "",
                        "transition-timing-function": ""
                    });
                    type === "transitioncanceled" ? reject() : resolve();
                }, false, function (ref) {
                    var target = ref.target;
                    return element === target;
                });
                addClass(element, "uk-transition");
                css(element, assign({
                    "transition-property": Object.keys(props).map(propName).join(","),
                    "transition-duration": duration + "ms",
                    "transition-timing-function": timing
                }, props));
            });
        }));
    }
    var Transition = {
        start: transition,
        stop: function (element) {
            trigger(element, "transitionend");
            return Promise.resolve();
        },
        cancel: function (element) {
            trigger(element, "transitioncanceled");
        },
        inProgress: function (element) {
            return hasClass(element, "uk-transition");
        }
    };
    var animationPrefix = "uk-animation-";
    var clsCancelAnimation = "uk-cancel-animation";
    function animate(element, animation, duration, origin, out) {
        var arguments$1 = arguments;
        if (duration === void 0) duration = 200;
        return Promise.all(toNodes(element).map(function (element) {
            return new Promise(function (resolve, reject) {
                if (hasClass(element, clsCancelAnimation)) {
                    requestAnimationFrame(function () {
                        return Promise.resolve().then(function () {
                            return animate.apply(void 0, arguments$1).then(resolve, reject);
                        });
                    });
                    return;
                }
                var cls = animation + " " + animationPrefix + (out ? "leave" : "enter");
                if (startsWith(animation, animationPrefix)) {
                    if (origin) {
                        cls += " uk-transform-origin-" + origin;
                    }
                    if (out) {
                        cls += " " + animationPrefix + "reverse";
                    }
                }
                reset();
                once(element, "animationend animationcancel", function (ref) {
                    var type = ref.type;
                    var hasReset = false;
                    if (type === "animationcancel") {
                        reject();
                        reset();
                    } else {
                        resolve();
                        Promise.resolve().then(function () {
                            hasReset = true;
                            reset();
                        });
                    }
                    requestAnimationFrame(function () {
                        if (!hasReset) {
                            addClass(element, clsCancelAnimation);
                            requestAnimationFrame(function () {
                                return removeClass(element, clsCancelAnimation);
                            });
                        }
                    });
                }, false, function (ref) {
                    var target = ref.target;
                    return element === target;
                });
                css(element, "animationDuration", duration + "ms");
                addClass(element, cls);
                function reset() {
                    css(element, "animationDuration", "");
                    removeClasses(element, animationPrefix + "\\S*");
                }
            });
        }));
    }
    var inProgress = new RegExp(animationPrefix + "(enter|leave)");
    var Animation = {
        in: function (element, animation, duration, origin) {
            return animate(element, animation, duration, origin, false);
        },
        out: function (element, animation, duration, origin) {
            return animate(element, animation, duration, origin, true);
        },
        inProgress: function (element) {
            return inProgress.test(attr(element, "class"));
        },
        cancel: function (element) {
            trigger(element, "animationcancel");
        }
    };
    var dirs = {
        width: ["x", "left", "right"],
        height: ["y", "top", "bottom"]
    };
    function positionAt(element, target, elAttach, targetAttach, elOffset, targetOffset, flip, boundary) {
        elAttach = getPos(elAttach);
        targetAttach = getPos(targetAttach);
        var flipped = {
            element: elAttach,
            target: targetAttach
        };
        if (!element || !target) {
            return flipped;
        }
        var dim = getDimensions(element);
        var targetDim = getDimensions(target);
        var position = targetDim;
        moveTo(position, elAttach, dim, -1);
        moveTo(position, targetAttach, targetDim, 1);
        elOffset = getOffsets(elOffset, dim.width, dim.height);
        targetOffset = getOffsets(targetOffset, targetDim.width, targetDim.height);
        elOffset["x"] += targetOffset["x"];
        elOffset["y"] += targetOffset["y"];
        position.left += elOffset["x"];
        position.top += elOffset["y"];
        if (flip) {
            var boundaries = [getDimensions(window$1(element))];
            if (boundary) {
                boundaries.unshift(getDimensions(boundary));
            }
            each(dirs, function (ref, prop) {
                var dir = ref[0];
                var align = ref[1];
                var alignFlip = ref[2];
                if (!(flip === true || includes(flip, dir))) {
                    return;
                }
                boundaries.some(function (boundary) {
                    var elemOffset = elAttach[dir] === align ? -dim[prop] : elAttach[dir] === alignFlip ? dim[prop] : 0;
                    var targetOffset = targetAttach[dir] === align ? targetDim[prop] : targetAttach[dir] === alignFlip ? -targetDim[prop] : 0;
                    if (position[align] < boundary[align] || position[align] + dim[prop] > boundary[alignFlip]) {
                        var centerOffset = dim[prop] / 2;
                        var centerTargetOffset = targetAttach[dir] === "center" ? -targetDim[prop] / 2 : 0;
                        return elAttach[dir] === "center" && (apply(centerOffset, centerTargetOffset) || apply(-centerOffset, -centerTargetOffset)) || apply(elemOffset, targetOffset);
                    }
                    function apply(elemOffset, targetOffset) {
                        var newVal = position[align] + elemOffset + targetOffset - elOffset[dir] * 2;
                        if (newVal >= boundary[align] && newVal + dim[prop] <= boundary[alignFlip]) {
                            position[align] = newVal;
                            ["element", "target"].forEach(function (el) {
                                flipped[el][dir] = !elemOffset ? flipped[el][dir] : flipped[el][dir] === dirs[prop][1] ? dirs[prop][2] : dirs[prop][1];
                            });
                            return true;
                        }
                    }
                });
            });
        }
        offset(element, position);
        return flipped;
    }
    function offset(element, coordinates) {
        element = toNode(element);
        if (coordinates) {
            var currentOffset = offset(element);
            var pos = css(element, "position");
            ["left", "top"].forEach(function (prop) {
                if (prop in coordinates) {
                    var value = css(element, prop);
                    css(element, prop, coordinates[prop] - currentOffset[prop] + toFloat(pos === "absolute" && value === "auto" ? position(element)[prop] : value));
                }
            });
            return;
        }
        return getDimensions(element);
    }
    function getDimensions(element) {
        element = toNode(element);
        var ref = window$1(element);
        var top = ref.pageYOffset;
        var left = ref.pageXOffset;
        if (isWindow(element)) {
            var height = element.innerHeight;
            var width = element.innerWidth;
            return {
                top: top,
                left: left,
                height: height,
                width: width,
                bottom: top + height,
                right: left + width
            };
        }
        var style, hidden;
        if (!isVisible(element)) {
            style = attr(element, "style");
            hidden = attr(element, "hidden");
            attr(element, {
                style: (style || "") + ";display:block !important;",
                hidden: null
            });
        }
        var rect = element.getBoundingClientRect();
        if (!isUndefined(style)) {
            attr(element, {
                style: style,
                hidden: hidden
            });
        }
        return {
            height: rect.height,
            width: rect.width,
            top: rect.top + top,
            left: rect.left + left,
            bottom: rect.bottom + top,
            right: rect.right + left
        };
    }
    function position(element) {
        element = toNode(element);
        var parent = element.offsetParent || docEl(element);
        var parentOffset = offset(parent);
        var ref = ["top", "left"].reduce(function (props, prop) {
            var propName$$1 = ucfirst(prop);
            props[prop] -= parentOffset[prop] + toFloat(css(element, "margin" + propName$$1)) + toFloat(css(parent, "border" + propName$$1 + "Width"));
            return props;
        }, offset(element));
        var top = ref.top;
        var left = ref.left;
        return {
            top: top,
            left: left
        };
    }
    var height = dimension("height");
    var width = dimension("width");
    function dimension(prop) {
        var propName$$1 = ucfirst(prop);
        return function (element, value) {
            element = toNode(element);
            if (isUndefined(value)) {
                if (isWindow(element)) {
                    return element["inner" + propName$$1];
                }
                if (isDocument(element)) {
                    var doc = element.documentElement;
                    return Math.max(doc["offset" + propName$$1], doc["scroll" + propName$$1]);
                }
                value = css(element, prop);
                value = value === "auto" ? element["offset" + propName$$1] : toFloat(value) || 0;
                return value - boxModelAdjust(prop, element);
            } else {
                css(element, prop, !value && value !== 0 ? "" : +value + boxModelAdjust(prop, element) + "px");
            }
        };
    }
    function boxModelAdjust(prop, element, sizing) {
        if (sizing === void 0) sizing = "border-box";
        return css(element, "boxSizing") === sizing ? dirs[prop].slice(1).map(ucfirst).reduce(function (value, prop) {
            return value + toFloat(css(element, "padding" + prop)) + toFloat(css(element, "border" + prop + "Width"));
        }, 0) : 0;
    }
    function moveTo(position, attach, dim, factor) {
        each(dirs, function (ref, prop) {
            var dir = ref[0];
            var align = ref[1];
            var alignFlip = ref[2];
            if (attach[dir] === alignFlip) {
                position[align] += dim[prop] * factor;
            } else if (attach[dir] === "center") {
                position[align] += dim[prop] * factor / 2;
            }
        });
    }
    function getPos(pos) {
        var x = /left|center|right/;
        var y = /top|center|bottom/;
        pos = (pos || "").split(" ");
        if (pos.length === 1) {
            pos = x.test(pos[0]) ? pos.concat(["center"]) : y.test(pos[0]) ? ["center"].concat(pos) : ["center", "center"];
        }
        return {
            x: x.test(pos[0]) ? pos[0] : "center",
            y: y.test(pos[1]) ? pos[1] : "center"
        };
    }
    function getOffsets(offsets, width, height) {
        var ref = (offsets || "").split(" ");
        var x = ref[0];
        var y = ref[1];
        return {
            x: x ? toFloat(x) * (endsWith(x, "%") ? width / 100 : 1) : 0,
            y: y ? toFloat(y) * (endsWith(y, "%") ? height / 100 : 1) : 0
        };
    }
    function flipPosition(pos) {
        switch (pos) {
            case "left":
                return "right";

            case "right":
                return "left";

            case "top":
                return "bottom";

            case "bottom":
                return "top";

            default:
                return pos;
        }
    }
    function isInView(element, topOffset, leftOffset) {
        if (topOffset === void 0) topOffset = 0;
        if (leftOffset === void 0) leftOffset = 0;
        if (!isVisible(element)) {
            return false;
        }
        element = toNode(element);
        var win = window$1(element);
        var client = element.getBoundingClientRect();
        var bounding = {
            top: -topOffset,
            left: -leftOffset,
            bottom: topOffset + height(win),
            right: leftOffset + width(win)
        };
        return intersectRect(client, bounding) || pointInRect({
            x: client.left,
            y: client.top
        }, bounding);
    }
    function scrolledOver(element, heightOffset) {
        if (heightOffset === void 0) heightOffset = 0;
        if (!isVisible(element)) {
            return 0;
        }
        element = toNode(element);
        var win = window$1(element);
        var doc = document$1(element);
        var elHeight = element.offsetHeight + heightOffset;
        var ref = offsetPosition(element);
        var top = ref[0];
        var vp = height(win);
        var vh = vp + Math.min(0, top - vp);
        var diff = Math.max(0, vp - (height(doc) + heightOffset - (top + elHeight)));
        return clamp((vh + win.pageYOffset - top) / ((vh + (elHeight - (diff < vp ? diff : 0))) / 100) / 100);
    }
    function scrollTop(element, top) {
        element = toNode(element);
        if (isWindow(element) || isDocument(element)) {
            var ref = window$1(element);
            var scrollTo = ref.scrollTo;
            var pageXOffset = ref.pageXOffset;
            scrollTo(pageXOffset, top);
        } else {
            element.scrollTop = top;
        }
    }
    function offsetPosition(element) {
        var offset = [0, 0];
        do {
            offset[0] += element.offsetTop;
            offset[1] += element.offsetLeft;
            if (css(element, "position") === "fixed") {
                var win = window$1(element);
                offset[0] += win.pageYOffset;
                offset[1] += win.pageXOffset;
                return offset;
            }
        } while (element = element.offsetParent);
        return offset;
    }
    function window$1(element) {
        return isWindow(element) ? element : document$1(element).defaultView;
    }
    function document$1(element) {
        return toNode(element).ownerDocument;
    }
    function docEl(element) {
        return document$1(element).documentElement;
    }
    var fastdom = {
        reads: [],
        writes: [],
        read: function (task) {
            this.reads.push(task);
            scheduleFlush();
            return task;
        },
        write: function (task) {
            this.writes.push(task);
            scheduleFlush();
            return task;
        },
        clear: function (task) {
            return remove$1(this.reads, task) || remove$1(this.writes, task);
        },
        flush: function () {
            runTasks(this.reads);
            runTasks(this.writes.splice(0, this.writes.length));
            this.scheduled = false;
            if (this.reads.length || this.writes.length) {
                scheduleFlush();
            }
        }
    };
    function scheduleFlush() {
        if (!fastdom.scheduled) {
            fastdom.scheduled = true;
            requestAnimationFrame(fastdom.flush.bind(fastdom));
        }
    }
    function runTasks(tasks) {
        var task;
        while (task = tasks.shift()) {
            task();
        }
    }
    function remove$1(array, item) {
        var index = array.indexOf(item);
        return !!~index && !!array.splice(index, 1);
    }
    function MouseTracker() { }
    MouseTracker.prototype = {
        positions: [],
        position: null,
        init: function () {
            var this$1 = this;
            this.positions = [];
            this.position = null;
            var ticking = false;
            this.unbind = on(document, "mousemove", function (e) {
                if (ticking) {
                    return;
                }
                setTimeout(function () {
                    var time = Date.now();
                    var ref = this$1.positions;
                    var length = ref.length;
                    if (length && time - this$1.positions[length - 1].time > 100) {
                        this$1.positions.splice(0, length);
                    }
                    this$1.positions.push({
                        time: time,
                        x: e.pageX,
                        y: e.pageY
                    });
                    if (this$1.positions.length > 5) {
                        this$1.positions.shift();
                    }
                    ticking = false;
                }, 5);
                ticking = true;
            });
        },
        cancel: function () {
            if (this.unbind) {
                this.unbind();
            }
        },
        movesTo: function (target) {
            if (this.positions.length < 2) {
                return false;
            }
            var p = offset(target);
            var position$$1 = this.positions[this.positions.length - 1];
            var ref = this.positions;
            var prevPos = ref[0];
            if (p.left <= position$$1.x && position$$1.x <= p.right && p.top <= position$$1.y && position$$1.y <= p.bottom) {
                return false;
            }
            var points = [[{
                x: p.left,
                y: p.top
            }, {
                x: p.right,
                y: p.bottom
            }], [{
                x: p.right,
                y: p.top
            }, {
                x: p.left,
                y: p.bottom
            }]];
            if (p.right <= position$$1.x); else if (p.left >= position$$1.x) {
                points[0].reverse();
                points[1].reverse();
            } else if (p.bottom <= position$$1.y) {
                points[0].reverse();
            } else if (p.top >= position$$1.y) {
                points[1].reverse();
            }
            return !!points.reduce(function (result, point) {
                return result + (slope(prevPos, point[0]) < slope(position$$1, point[0]) && slope(prevPos, point[1]) > slope(position$$1, point[1]));
            }, 0);
        }
    };
    function slope(a, b) {
        return (b.y - a.y) / (b.x - a.x);
    }
    var strats = {};
    strats.events = strats.created = strats.beforeConnect = strats.connected = strats.beforeDisconnect = strats.disconnected = strats.destroy = concatStrat;
    strats.args = function (parentVal, childVal) {
        return concatStrat(childVal || parentVal);
    };
    strats.update = function (parentVal, childVal) {
        return sortBy(concatStrat(parentVal, isFunction(childVal) ? {
            read: childVal
        } : childVal), "order");
    };
    strats.props = function (parentVal, childVal) {
        if (isArray(childVal)) {
            childVal = childVal.reduce(function (value, key) {
                value[key] = String;
                return value;
            }, {});
        }
        return strats.methods(parentVal, childVal);
    };
    strats.computed = strats.methods = function (parentVal, childVal) {
        return childVal ? parentVal ? assign({}, parentVal, childVal) : childVal : parentVal;
    };
    strats.data = function (parentVal, childVal, vm) {
        if (!vm) {
            if (!childVal) {
                return parentVal;
            }
            if (!parentVal) {
                return childVal;
            }
            return function (vm) {
                return mergeFnData(parentVal, childVal, vm);
            };
        }
        return mergeFnData(parentVal, childVal, vm);
    };
    function mergeFnData(parentVal, childVal, vm) {
        return strats.computed(isFunction(parentVal) ? parentVal.call(vm, vm) : parentVal, isFunction(childVal) ? childVal.call(vm, vm) : childVal);
    }
    function concatStrat(parentVal, childVal) {
        parentVal = parentVal && !isArray(parentVal) ? [parentVal] : parentVal;
        return childVal ? parentVal ? parentVal.concat(childVal) : isArray(childVal) ? childVal : [childVal] : parentVal;
    }
    function defaultStrat(parentVal, childVal) {
        return isUndefined(childVal) ? parentVal : childVal;
    }
    function mergeOptions(parent, child, vm) {
        var options = {};
        if (isFunction(child)) {
            child = child.options;
        }
        if (child.extends) {
            parent = mergeOptions(parent, child.extends, vm);
        }
        if (child.mixins) {
            for (var i = 0, l = child.mixins.length; i < l; i++) {
                parent = mergeOptions(parent, child.mixins[i], vm);
            }
        }
        for (var key in parent) {
            mergeKey(key);
        }
        for (var key$1 in child) {
            if (!hasOwn(parent, key$1)) {
                mergeKey(key$1);
            }
        }
        function mergeKey(key) {
            options[key] = (strats[key] || defaultStrat)(parent[key], child[key], vm);
        }
        return options;
    }
    function parseOptions(options, args) {
        var obj;
        if (args === void 0) args = [];
        try {
            return !options ? {} : startsWith(options, "{") ? JSON.parse(options) : args.length && !includes(options, ":") ? (obj = {},
                obj[args[0]] = options, obj) : options.split(";").reduce(function (options, option) {
                    var ref = option.split(/:(.*)/);
                    var key = ref[0];
                    var value = ref[1];
                    if (key && !isUndefined(value)) {
                        options[key.trim()] = value.trim();
                    }
                    return options;
                }, {});
        } catch (e) {
            return {};
        }
    }
    var id = 0;
    var Player = function (el) {
        this.id = ++id;
        this.el = toNode(el);
    };
    Player.prototype.isVideo = function () {
        return this.isYoutube() || this.isVimeo() || this.isHTML5();
    };
    Player.prototype.isHTML5 = function () {
        return this.el.tagName === "VIDEO";
    };
    Player.prototype.isIFrame = function () {
        return this.el.tagName === "IFRAME";
    };
    Player.prototype.isYoutube = function () {
        return this.isIFrame() && !!this.el.src.match(/\/\/.*?youtube(-nocookie)?\.[a-z]+\/(watch\?v=[^&\s]+|embed)|youtu\.be\/.*/);
    };
    Player.prototype.isVimeo = function () {
        return this.isIFrame() && !!this.el.src.match(/vimeo\.com\/video\/.*/);
    };
    Player.prototype.enableApi = function () {
        var this$1 = this;
        if (this.ready) {
            return this.ready;
        }
        var youtube = this.isYoutube();
        var vimeo = this.isVimeo();
        var poller;
        if (youtube || vimeo) {
            return this.ready = new Promise(function (resolve) {
                once(this$1.el, "load", function () {
                    if (youtube) {
                        var listener = function () {
                            return post(this$1.el, {
                                event: "listening",
                                id: this$1.id
                            });
                        };
                        poller = setInterval(listener, 100);
                        listener();
                    }
                });
                listen(function (data$$1) {
                    return youtube && data$$1.id === this$1.id && data$$1.event === "onReady" || vimeo && Number(data$$1.player_id) === this$1.id;
                }).then(function () {
                    resolve();
                    poller && clearInterval(poller);
                });
                attr(this$1.el, "src", "" + this$1.el.src + (includes(this$1.el.src, "?") ? "&" : "?") + (youtube ? "enablejsapi=1" : "api=1&player_id=" + this$1.id));
            });
        }
        return Promise.resolve();
    };
    Player.prototype.play = function () {
        var this$1 = this;
        if (!this.isVideo()) {
            return;
        }
        if (this.isIFrame()) {
            this.enableApi().then(function () {
                return post(this$1.el, {
                    func: "playVideo",
                    method: "play"
                });
            });
        } else if (this.isHTML5()) {
            try {
                var promise = this.el.play();
                if (promise) {
                    promise.catch(noop);
                }
            } catch (e) { }
        }
    };
    Player.prototype.pause = function () {
        var this$1 = this;
        if (!this.isVideo()) {
            return;
        }
        if (this.isIFrame()) {
            this.enableApi().then(function () {
                return post(this$1.el, {
                    func: "pauseVideo",
                    method: "pause"
                });
            });
        } else if (this.isHTML5()) {
            this.el.pause();
        }
    };
    Player.prototype.mute = function () {
        var this$1 = this;
        if (!this.isVideo()) {
            return;
        }
        if (this.isIFrame()) {
            this.enableApi().then(function () {
                return post(this$1.el, {
                    func: "mute",
                    method: "setVolume",
                    value: 0
                });
            });
        } else if (this.isHTML5()) {
            this.el.muted = true;
            attr(this.el, "muted", "");
        }
    };
    function post(el, cmd) {
        try {
            el.contentWindow.postMessage(JSON.stringify(assign({
                event: "command"
            }, cmd)), "*");
        } catch (e) { }
    }
    function listen(cb) {
        return new Promise(function (resolve) {
            once(window, "message", function (_, data$$1) {
                return resolve(data$$1);
            }, false, function (ref) {
                var data$$1 = ref.data;
                if (!data$$1 || !isString(data$$1)) {
                    return;
                }
                try {
                    data$$1 = JSON.parse(data$$1);
                } catch (e) {
                    return;
                }
                return data$$1 && cb(data$$1);
            });
        });
    }
    var IntersectionObserver = "IntersectionObserver" in window ? window.IntersectionObserver : function () {
        function IntersectionObserverClass(callback, ref) {
            var this$1 = this;
            if (ref === void 0) ref = {};
            var rootMargin = ref.rootMargin;
            if (rootMargin === void 0) rootMargin = "0 0";
            this.targets = [];
            var ref$1 = (rootMargin || "0 0").split(" ").map(toFloat);
            var offsetTop = ref$1[0];
            var offsetLeft = ref$1[1];
            this.offsetTop = offsetTop;
            this.offsetLeft = offsetLeft;
            var pending;
            this.apply = function () {
                if (pending) {
                    return;
                }
                pending = requestAnimationFrame(function () {
                    return setTimeout(function () {
                        var records = this$1.takeRecords();
                        if (records.length) {
                            callback(records, this$1);
                        }
                        pending = false;
                    });
                });
            };
            this.off = on(window, "scroll resize load", this.apply, {
                passive: true,
                capture: true
            });
        }
        IntersectionObserverClass.prototype.takeRecords = function () {
            var this$1 = this;
            return this.targets.filter(function (entry) {
                var inView = isInView(entry.target, this$1.offsetTop, this$1.offsetLeft);
                if (entry.isIntersecting === null || inView ^ entry.isIntersecting) {
                    entry.isIntersecting = inView;
                    return true;
                }
            });
        };
        IntersectionObserverClass.prototype.observe = function (target) {
            this.targets.push({
                target: target,
                isIntersecting: null
            });
            this.apply();
        };
        IntersectionObserverClass.prototype.disconnect = function () {
            this.targets = [];
            this.off();
        };
        return IntersectionObserverClass;
    }();
    var touch = {}, swipeTimeout, touching;
    on(document, pointerDown, function (e) {
        if (touch.el) {
            touch = {};
        }
        var target = e.target;
        var ref = getPos$1(e);
        var x = ref.x;
        var y = ref.y;
        touch.el = "tagName" in target ? target : target.parentNode;
        touch.x = x;
        touch.y = y;
        touching = isTouch(e);
    });
    on(document, pointerUp, function (e) {
        var ref = getPos$1(e);
        var x = ref.x;
        var y = ref.y;
        if (touch.el && x && Math.abs(touch.x - x) > 100 || y && Math.abs(touch.y - y) > 100) {
            swipeTimeout = setTimeout(function () {
                if (touch.el) {
                    trigger(touch.el, "swipe");
                    trigger(touch.el, "swipe" + swipeDirection(touch.x, touch.y, x, y));
                }
                touch = {};
            });
        } else {
            touch = {};
        }
        setTimeout(function () {
            return touching = false;
        });
    });
    on(document, pointerCancel, cancelAll);
    function isTouch(e) {
        return e.pointerType === "touch" || e.touches || touching;
    }
    function getPos$1(e, prop) {
        if (prop === void 0) prop = "client";
        var touches = e.touches;
        var changedTouches = e.changedTouches;
        var ref = touches && touches[0] || changedTouches && changedTouches[0] || e;
        var x = ref[prop + "X"];
        var y = ref[prop + "Y"];
        return {
            x: x,
            y: y
        };
    }
    function swipeDirection(x1, y1, x2, y2) {
        return Math.abs(x1 - x2) >= Math.abs(y1 - y2) ? x1 - x2 > 0 ? "Left" : "Right" : y1 - y2 > 0 ? "Up" : "Down";
    }
    function cancelAll() {
        swipeTimeout && clearTimeout(swipeTimeout);
        swipeTimeout = null;
        touch = {};
    }
    var util = Object.freeze({
        ajax: ajax,
        getImage: getImage,
        transition: transition,
        Transition: Transition,
        animate: animate,
        Animation: Animation,
        attr: attr,
        hasAttr: hasAttr,
        removeAttr: removeAttr,
        data: data,
        addClass: addClass,
        removeClass: removeClass,
        removeClasses: removeClasses,
        replaceClass: replaceClass,
        hasClass: hasClass,
        toggleClass: toggleClass,
        positionAt: positionAt,
        offset: offset,
        position: position,
        height: height,
        width: width,
        boxModelAdjust: boxModelAdjust,
        flipPosition: flipPosition,
        isInView: isInView,
        scrolledOver: scrolledOver,
        scrollTop: scrollTop,
        offsetPosition: offsetPosition,
        ready: ready,
        index: index,
        getIndex: getIndex,
        empty: empty,
        html: html,
        prepend: prepend,
        append: append,
        before: before,
        after: after,
        remove: remove,
        wrapAll: wrapAll,
        wrapInner: wrapInner,
        unwrap: unwrap,
        fragment: fragment,
        apply: apply,
        $: $,
        $$: $$,
        isIE: isIE,
        isRtl: isRtl,
        hasTouch: hasTouch,
        pointerDown: pointerDown,
        pointerMove: pointerMove,
        pointerUp: pointerUp,
        pointerEnter: pointerEnter,
        pointerLeave: pointerLeave,
        pointerCancel: pointerCancel,
        on: on,
        off: off,
        once: once,
        trigger: trigger,
        createEvent: createEvent,
        toEventTargets: toEventTargets,
        preventClick: preventClick,
        fastdom: fastdom,
        isVoidElement: isVoidElement,
        isVisible: isVisible,
        selInput: selInput,
        isInput: isInput,
        filter: filter,
        within: within,
        bind: bind,
        hasOwn: hasOwn,
        hyphenate: hyphenate,
        camelize: camelize,
        ucfirst: ucfirst,
        startsWith: startsWith,
        endsWith: endsWith,
        includes: includes,
        isArray: isArray,
        isFunction: isFunction,
        isObject: isObject,
        isPlainObject: isPlainObject,
        isWindow: isWindow,
        isDocument: isDocument,
        isJQuery: isJQuery,
        isNode: isNode,
        isNodeCollection: isNodeCollection,
        isBoolean: isBoolean,
        isString: isString,
        isNumber: isNumber,
        isNumeric: isNumeric,
        isUndefined: isUndefined,
        toBoolean: toBoolean,
        toNumber: toNumber,
        toFloat: toFloat,
        toNode: toNode,
        toNodes: toNodes,
        toList: toList,
        toMs: toMs,
        isEqual: isEqual,
        swap: swap,
        assign: assign,
        each: each,
        sortBy: sortBy,
        clamp: clamp,
        noop: noop,
        intersectRect: intersectRect,
        pointInRect: pointInRect,
        Dimensions: Dimensions,
        MouseTracker: MouseTracker,
        mergeOptions: mergeOptions,
        parseOptions: parseOptions,
        Player: Player,
        Promise: Promise,
        Deferred: Deferred,
        IntersectionObserver: IntersectionObserver,
        query: query,
        queryAll: queryAll,
        find: find,
        findAll: findAll,
        matches: matches,
        closest: closest,
        parents: parents,
        escape: escape,
        css: css,
        getStyles: getStyles,
        getStyle: getStyle,
        getCssVar: getCssVar,
        propName: propName,
        isTouch: isTouch,
        getPos: getPos$1
    });
    function componentAPI(UIkit) {
        var DATA = UIkit.data;
        var components = {};
        UIkit.component = function (name, options) {
            if (!options) {
                if (isPlainObject(components[name])) {
                    components[name] = UIkit.extend(components[name]);
                }
                return components[name];
            }
            UIkit[name] = function (element, data$$1) {
                var i = arguments.length, argsArray = Array(i);
                while (i--) argsArray[i] = arguments[i];
                var component = UIkit.component(name);
                if (isPlainObject(element)) {
                    return new component({
                        data: element
                    });
                }
                if (component.options.functional) {
                    return new component({
                        data: [].concat(argsArray)
                    });
                }
                return element && element.nodeType ? init(element) : $$(element).map(init)[0];
                function init(element) {
                    var instance = UIkit.getComponent(element, name);
                    if (instance) {
                        if (!data$$1) {
                            return instance;
                        } else {
                            instance.$destroy();
                        }
                    }
                    return new component({
                        el: element,
                        data: data$$1
                    });
                }
            };
            var opt = isPlainObject(options) ? assign({}, options) : options.options;
            opt.name = name;
            if (opt.install) {
                opt.install(UIkit, opt, name);
            }
            if (UIkit._initialized && !opt.functional) {
                var id = hyphenate(name);
                fastdom.read(function () {
                    return UIkit[name]("[uk-" + id + "],[data-uk-" + id + "]");
                });
            }
            return components[name] = isPlainObject(options) ? opt : options;
        };
        UIkit.getComponents = function (element) {
            return element && element[DATA] || {};
        };
        UIkit.getComponent = function (element, name) {
            return UIkit.getComponents(element)[name];
        };
        UIkit.connect = function (node) {
            if (node[DATA]) {
                for (var name in node[DATA]) {
                    node[DATA][name]._callConnected();
                }
            }
            for (var i = 0; i < node.attributes.length; i++) {
                var name$1 = getComponentName(node.attributes[i].name);
                if (name$1 && name$1 in components) {
                    UIkit[name$1](node);
                }
            }
        };
        UIkit.disconnect = function (node) {
            for (var name in node[DATA]) {
                node[DATA][name]._callDisconnected();
            }
        };
    }
    function getComponentName(attribute) {
        return startsWith(attribute, "uk-") || startsWith(attribute, "data-uk-") ? camelize(attribute.replace("data-uk-", "").replace("uk-", "")) : false;
    }
    function boot(UIkit) {
        var connect = UIkit.connect;
        var disconnect = UIkit.disconnect;
        if (!("MutationObserver" in window)) {
            return;
        }
        if (document.body) {
            init();
        } else {
            new MutationObserver(function () {
                if (document.body) {
                    this.disconnect();
                    init();
                }
            }).observe(document, {
                childList: true,
                subtree: true
            });
        }
        function init() {
            apply$$1(document.body, connect);
            fastdom.flush();
            new MutationObserver(function (mutations) {
                return mutations.forEach(applyMutation);
            }).observe(document, {
                childList: true,
                subtree: true,
                characterData: true,
                attributes: true
            });
            UIkit._initialized = true;
        }
        function applyMutation(mutation) {
            var target = mutation.target;
            var type = mutation.type;
            var update = type !== "attributes" ? applyChildList(mutation) : applyAttribute(mutation);
            update && UIkit.update(target);
        }
        function applyAttribute(ref) {
            var target = ref.target;
            var attributeName = ref.attributeName;
            if (attributeName === "href") {
                return true;
            }
            var name = getComponentName(attributeName);
            if (!name || !(name in UIkit)) {
                return;
            }
            if (hasAttr(target, attributeName)) {
                UIkit[name](target);
                return true;
            }
            var component = UIkit.getComponent(target, name);
            if (component) {
                component.$destroy();
                return true;
            }
        }
        function applyChildList(ref) {
            var addedNodes = ref.addedNodes;
            var removedNodes = ref.removedNodes;
            for (var i = 0; i < addedNodes.length; i++) {
                apply$$1(addedNodes[i], connect);
            }
            for (var i$1 = 0; i$1 < removedNodes.length; i$1++) {
                apply$$1(removedNodes[i$1], disconnect);
            }
            return true;
        }
        function apply$$1(node, fn) {
            if (node.nodeType !== 1 || hasAttr(node, "uk-no-boot")) {
                return;
            }
            fn(node);
            node = node.firstElementChild;
            while (node) {
                var next = node.nextElementSibling;
                apply$$1(node, fn);
                node = next;
            }
        }
    }
    function globalAPI(UIkit) {
        var DATA = UIkit.data;
        UIkit.use = function (plugin) {
            if (plugin.installed) {
                return;
            }
            plugin.call(null, this);
            plugin.installed = true;
            return this;
        };
        UIkit.mixin = function (mixin, component) {
            component = (isString(component) ? UIkit.component(component) : component) || this;
            component.options = mergeOptions(component.options, mixin);
        };
        UIkit.extend = function (options) {
            options = options || {};
            var Super = this;
            var Sub = function UIkitComponent(options) {
                this._init(options);
            };
            Sub.prototype = Object.create(Super.prototype);
            Sub.prototype.constructor = Sub;
            Sub.options = mergeOptions(Super.options, options);
            Sub.super = Super;
            Sub.extend = Super.extend;
            return Sub;
        };
        UIkit.update = function (element, e) {
            element = element ? toNode(element) : document.body;
            path(element, function (element) {
                return update(element[DATA], e);
            });
            apply(element, function (element) {
                return update(element[DATA], e);
            });
        };
        var container;
        Object.defineProperty(UIkit, "container", {
            get: function () {
                return container || document.body;
            },
            set: function (element) {
                container = $(element);
            }
        });
        function update(data$$1, e) {
            if (!data$$1) {
                return;
            }
            for (var name in data$$1) {
                if (data$$1[name]._connected) {
                    data$$1[name]._callUpdate(e);
                }
            }
        }
        function path(node, fn) {
            if (node && node !== document.body && node.parentNode) {
                path(node.parentNode, fn);
                fn(node.parentNode);
            }
        }
    }
    function hooksAPI(UIkit) {
        UIkit.prototype._callHook = function (hook) {
            var this$1 = this;
            var handlers = this.$options[hook];
            if (handlers) {
                handlers.forEach(function (handler) {
                    return handler.call(this$1);
                });
            }
        };
        UIkit.prototype._callConnected = function () {
            if (this._connected) {
                return;
            }
            this._data = {};
            this._computeds = {};
            this._initProps();
            this._callHook("beforeConnect");
            this._connected = true;
            this._initEvents();
            this._initObserver();
            this._callHook("connected");
            this._callUpdate();
        };
        UIkit.prototype._callDisconnected = function () {
            if (!this._connected) {
                return;
            }
            this._callHook("beforeDisconnect");
            if (this._observer) {
                this._observer.disconnect();
                this._observer = null;
            }
            this._unbindEvents();
            this._callHook("disconnected");
            this._connected = false;
        };
        UIkit.prototype._callUpdate = function (e) {
            var this$1 = this;
            if (e === void 0) e = "update";
            var type = e.type || e;
            if (includes(["update", "resize"], type)) {
                this._callWatches();
            }
            var updates = this.$options.update;
            var ref = this._frames;
            var reads = ref.reads;
            var writes = ref.writes;
            if (!updates) {
                return;
            }
            updates.forEach(function (ref, i) {
                var read = ref.read;
                var write = ref.write;
                var events = ref.events;
                if (type !== "update" && !includes(events, type)) {
                    return;
                }
                if (read && !includes(fastdom.reads, reads[i])) {
                    reads[i] = fastdom.read(function () {
                        var result = this$1._connected && read.call(this$1, this$1._data, type);
                        if (result === false && write) {
                            fastdom.clear(writes[i]);
                        } else if (isPlainObject(result)) {
                            assign(this$1._data, result);
                        }
                    });
                }
                if (write && !includes(fastdom.writes, writes[i])) {
                    writes[i] = fastdom.write(function () {
                        return this$1._connected && write.call(this$1, this$1._data, type);
                    });
                }
            });
        };
    }
    function stateAPI(UIkit) {
        var uid = 0;
        UIkit.prototype._init = function (options) {
            options = options || {};
            options.data = normalizeData(options, this.constructor.options);
            this.$options = mergeOptions(this.constructor.options, options, this);
            this.$el = null;
            this.$props = {};
            this._frames = {
                reads: {},
                writes: {}
            };
            this._events = [];
            this._uid = uid++;
            this._initData();
            this._initMethods();
            this._initComputeds();
            this._callHook("created");
            if (options.el) {
                this.$mount(options.el);
            }
        };
        UIkit.prototype._initData = function () {
            var ref = this.$options;
            var data$$1 = ref.data;
            if (data$$1 === void 0) data$$1 = {};
            for (var key in data$$1) {
                this.$props[key] = this[key] = data$$1[key];
            }
        };
        UIkit.prototype._initMethods = function () {
            var ref = this.$options;
            var methods = ref.methods;
            if (methods) {
                for (var key in methods) {
                    this[key] = bind(methods[key], this);
                }
            }
        };
        UIkit.prototype._initComputeds = function () {
            var ref = this.$options;
            var computed = ref.computed;
            this._computeds = {};
            if (computed) {
                for (var key in computed) {
                    registerComputed(this, key, computed[key]);
                }
            }
        };
        UIkit.prototype._callWatches = function () {
            var ref = this;
            var computed = ref.$options.computed;
            var _computeds = ref._computeds;
            for (var key in _computeds) {
                var value = _computeds[key];
                delete _computeds[key];
                if (computed[key].watch && !isEqual(value, this[key])) {
                    computed[key].watch.call(this, this[key], value);
                }
            }
        };
        UIkit.prototype._initProps = function (props) {
            var key;
            props = props || getProps(this.$options, this.$name);
            for (key in props) {
                if (!isUndefined(props[key])) {
                    this.$props[key] = props[key];
                }
            }
            var exclude = [this.$options.computed, this.$options.methods];
            for (key in this.$props) {
                if (key in props && notIn(exclude, key)) {
                    this[key] = this.$props[key];
                }
            }
        };
        UIkit.prototype._initEvents = function () {
            var this$1 = this;
            var ref = this.$options;
            var events = ref.events;
            if (events) {
                events.forEach(function (event) {
                    if (!hasOwn(event, "handler")) {
                        for (var key in event) {
                            registerEvent(this$1, event[key], key);
                        }
                    } else {
                        registerEvent(this$1, event);
                    }
                });
            }
        };
        UIkit.prototype._unbindEvents = function () {
            this._events.forEach(function (unbind) {
                return unbind();
            });
            this._events = [];
        };
        UIkit.prototype._initObserver = function () {
            var this$1 = this;
            var ref = this.$options;
            var attrs = ref.attrs;
            var props = ref.props;
            var el = ref.el;
            if (this._observer || !props || attrs === false) {
                return;
            }
            attrs = isArray(attrs) ? attrs : Object.keys(props);
            this._observer = new MutationObserver(function () {
                var data$$1 = getProps(this$1.$options, this$1.$name);
                if (attrs.some(function (key) {
                    return !isUndefined(data$$1[key]) && data$$1[key] !== this$1.$props[key];
                })) {
                    this$1.$reset();
                }
            });
            var filter$$1 = attrs.map(function (key) {
                return hyphenate(key);
            }).concat(this.$name);
            this._observer.observe(el, {
                attributes: true,
                attributeFilter: filter$$1.concat(filter$$1.map(function (key) {
                    return "data-" + key;
                }))
            });
        };
        function getProps(opts, name) {
            var data$$1 = {};
            var args = opts.args;
            if (args === void 0) args = [];
            var props = opts.props;
            if (props === void 0) props = {};
            var el = opts.el;
            if (!props) {
                return data$$1;
            }
            for (var key in props) {
                var prop = hyphenate(key);
                var value = data(el, prop);
                if (!isUndefined(value)) {
                    value = props[key] === Boolean && value === "" ? true : coerce(props[key], value);
                    if (prop === "target" && (!value || startsWith(value, "_"))) {
                        continue;
                    }
                    data$$1[key] = value;
                }
            }
            var options = parseOptions(data(el, name), args);
            for (var key$1 in options) {
                var prop$1 = camelize(key$1);
                if (props[prop$1] !== undefined) {
                    data$$1[prop$1] = coerce(props[prop$1], options[key$1]);
                }
            }
            return data$$1;
        }
        function registerComputed(component, key, cb) {
            Object.defineProperty(component, key, {
                enumerable: true,
                get: function () {
                    var _computeds = component._computeds;
                    var $props = component.$props;
                    var $el = component.$el;
                    if (!hasOwn(_computeds, key)) {
                        _computeds[key] = (cb.get || cb).call(component, $props, $el);
                    }
                    return _computeds[key];
                },
                set: function (value) {
                    var _computeds = component._computeds;
                    _computeds[key] = cb.set ? cb.set.call(component, value) : value;
                    if (isUndefined(_computeds[key])) {
                        delete _computeds[key];
                    }
                }
            });
        }
        function registerEvent(component, event, key) {
            if (!isPlainObject(event)) {
                event = {
                    name: key,
                    handler: event
                };
            }
            var name = event.name;
            var el = event.el;
            var handler = event.handler;
            var capture = event.capture;
            var passive = event.passive;
            var delegate = event.delegate;
            var filter$$1 = event.filter;
            var self = event.self;
            el = isFunction(el) ? el.call(component) : el || component.$el;
            if (isArray(el)) {
                el.forEach(function (el) {
                    return registerEvent(component, assign({}, event, {
                        el: el
                    }), key);
                });
                return;
            }
            if (!el || filter$$1 && !filter$$1.call(component)) {
                return;
            }
            handler = detail(isString(handler) ? component[handler] : bind(handler, component));
            if (self) {
                handler = selfFilter(handler);
            }
            component._events.push(on(el, name, !delegate ? null : isString(delegate) ? delegate : delegate.call(component), handler, isBoolean(passive) ? {
                passive: passive,
                capture: capture
            } : capture));
        }
        function selfFilter(handler) {
            return function selfHandler(e) {
                if (e.target === e.currentTarget || e.target === e.current) {
                    return handler.call(null, e);
                }
            };
        }
        function notIn(options, key) {
            return options.every(function (arr) {
                return !arr || !hasOwn(arr, key);
            });
        }
        function detail(listener) {
            return function (e) {
                return isArray(e.detail) ? listener.apply(void 0, [e].concat(e.detail)) : listener(e);
            };
        }
        function coerce(type, value) {
            if (type === Boolean) {
                return toBoolean(value);
            } else if (type === Number) {
                return toNumber(value);
            } else if (type === "list") {
                return toList(value);
            }
            return type ? type(value) : value;
        }
        function normalizeData(ref, ref$1) {
            var data$$1 = ref.data;
            var el = ref.el;
            var args = ref$1.args;
            var props = ref$1.props;
            if (props === void 0) props = {};
            data$$1 = isArray(data$$1) ? args && args.length ? data$$1.slice(0, args.length).reduce(function (data$$1, value, index$$1) {
                if (isPlainObject(value)) {
                    assign(data$$1, value);
                } else {
                    data$$1[args[index$$1]] = value;
                }
                return data$$1;
            }, {}) : undefined : data$$1;
            if (data$$1) {
                for (var key in data$$1) {
                    if (isUndefined(data$$1[key])) {
                        delete data$$1[key];
                    } else {
                        data$$1[key] = props[key] ? coerce(props[key], data$$1[key], el) : data$$1[key];
                    }
                }
            }
            return data$$1;
        }
    }
    function instanceAPI(UIkit) {
        var DATA = UIkit.data;
        UIkit.prototype.$mount = function (el) {
            var ref = this.$options;
            var name = ref.name;
            if (!el[DATA]) {
                el[DATA] = {};
            }
            if (el[DATA][name]) {
                return;
            }
            el[DATA][name] = this;
            this.$el = this.$options.el = this.$options.el || el;
            if (within(el, document)) {
                this._callConnected();
            }
        };
        UIkit.prototype.$emit = function (e) {
            this._callUpdate(e);
        };
        UIkit.prototype.$reset = function () {
            this._callDisconnected();
            this._callConnected();
        };
        UIkit.prototype.$destroy = function (removeEl) {
            if (removeEl === void 0) removeEl = false;
            var ref = this.$options;
            var el = ref.el;
            var name = ref.name;
            if (el) {
                this._callDisconnected();
            }
            this._callHook("destroy");
            if (!el || !el[DATA]) {
                return;
            }
            delete el[DATA][name];
            if (!Object.keys(el[DATA]).length) {
                delete el[DATA];
            }
            if (removeEl) {
                remove(this.$el);
            }
        };
        UIkit.prototype.$create = function (component, element, data$$1) {
            return UIkit[component](element, data$$1);
        };
        UIkit.prototype.$update = UIkit.update;
        UIkit.prototype.$getComponent = UIkit.getComponent;
        var names = {};
        Object.defineProperties(UIkit.prototype, {
            $container: Object.getOwnPropertyDescriptor(UIkit, "container"),
            $name: {
                get: function () {
                    var ref = this.$options;
                    var name = ref.name;
                    if (!names[name]) {
                        names[name] = UIkit.prefix + hyphenate(name);
                    }
                    return names[name];
                }
            }
        });
    }
    var UIkit = function (options) {
        this._init(options);
    };
    UIkit.util = util;
    UIkit.data = "__uikit__";
    UIkit.prefix = "uk-";
    UIkit.options = {};
    globalAPI(UIkit);
    hooksAPI(UIkit);
    stateAPI(UIkit);
    componentAPI(UIkit);
    instanceAPI(UIkit);
    var Class = {
        connected: function () {
            !hasClass(this.$el, this.$name) && addClass(this.$el, this.$name);
        }
    };
    var Togglable = {
        props: {
            cls: Boolean,
            animation: "list",
            duration: Number,
            origin: String,
            transition: String,
            queued: Boolean
        },
        data: {
            cls: false,
            animation: [false],
            duration: 200,
            origin: false,
            transition: "linear",
            queued: false,
            initProps: {
                overflow: "",
                height: "",
                paddingTop: "",
                paddingBottom: "",
                marginTop: "",
                marginBottom: ""
            },
            hideProps: {
                overflow: "hidden",
                height: 0,
                paddingTop: 0,
                paddingBottom: 0,
                marginTop: 0,
                marginBottom: 0
            }
        },
        computed: {
            hasAnimation: function (ref) {
                var animation = ref.animation;
                return !!animation[0];
            },
            hasTransition: function (ref) {
                var animation = ref.animation;
                return this.hasAnimation && animation[0] === true;
            }
        },
        methods: {
            toggleElement: function (targets, show, animate$$1) {
                var this$1 = this;
                return new Promise(function (resolve) {
                    targets = toNodes(targets);
                    var all = function (targets) {
                        return Promise.all(targets.map(function (el) {
                            return this$1._toggleElement(el, show, animate$$1);
                        }));
                    };
                    var toggled = targets.filter(function (el) {
                        return this$1.isToggled(el);
                    });
                    var untoggled = targets.filter(function (el) {
                        return !includes(toggled, el);
                    });
                    var p;
                    if (!this$1.queued || !isUndefined(animate$$1) || !isUndefined(show) || !this$1.hasAnimation || targets.length < 2) {
                        p = all(untoggled.concat(toggled));
                    } else {
                        var body = document.body;
                        var scroll = body.scrollTop;
                        var el = toggled[0];
                        var inProgress = Animation.inProgress(el) && hasClass(el, "uk-animation-leave") || Transition.inProgress(el) && el.style.height === "0px";
                        p = all(toggled);
                        if (!inProgress) {
                            p = p.then(function () {
                                var p = all(untoggled);
                                body.scrollTop = scroll;
                                return p;
                            });
                        }
                    }
                    p.then(resolve, noop);
                });
            },
            toggleNow: function (targets, show) {
                var this$1 = this;
                return new Promise(function (resolve) {
                    return Promise.all(toNodes(targets).map(function (el) {
                        return this$1._toggleElement(el, show, false);
                    })).then(resolve, noop);
                });
            },
            isToggled: function (el) {
                var nodes = toNodes(el || this.$el);
                return this.cls ? hasClass(nodes, this.cls.split(" ")[0]) : !hasAttr(nodes, "hidden");
            },
            updateAria: function (el) {
                if (this.cls === false) {
                    attr(el, "aria-hidden", !this.isToggled(el));
                }
            },
            _toggleElement: function (el, show, animate$$1) {
                var this$1 = this;
                show = isBoolean(show) ? show : Animation.inProgress(el) ? hasClass(el, "uk-animation-leave") : Transition.inProgress(el) ? el.style.height === "0px" : !this.isToggled(el);
                if (!trigger(el, "before" + (show ? "show" : "hide"), [this])) {
                    return Promise.reject();
                }
                var promise = (isFunction(animate$$1) ? animate$$1 : animate$$1 === false || !this.hasAnimation ? this._toggle : this.hasTransition ? toggleHeight(this) : toggleAnimation(this))(el, show);
                trigger(el, show ? "show" : "hide", [this]);
                var final = function () {
                    trigger(el, show ? "shown" : "hidden", [this$1]);
                    this$1.$update(el);
                };
                return promise ? promise.then(final) : Promise.resolve(final());
            },
            _toggle: function (el, toggled) {
                if (!el) {
                    return;
                }
                toggled = Boolean(toggled);
                var changed;
                if (this.cls) {
                    changed = includes(this.cls, " ") || toggled !== hasClass(el, this.cls);
                    changed && toggleClass(el, this.cls, includes(this.cls, " ") ? undefined : toggled);
                } else {
                    changed = toggled === hasAttr(el, "hidden");
                    changed && attr(el, "hidden", !toggled ? "" : null);
                }
                $$("[autofocus]", el).some(function (el) {
                    return isVisible(el) ? el.focus() || true : el.blur();
                });
                this.updateAria(el);
                changed && this.$update(el);
            }
        }
    };
    function toggleHeight(ref) {
        var isToggled = ref.isToggled;
        var duration = ref.duration;
        var initProps = ref.initProps;
        var hideProps = ref.hideProps;
        var transition$$1 = ref.transition;
        var _toggle = ref._toggle;
        return function (el, show) {
            var inProgress = Transition.inProgress(el);
            var inner = el.hasChildNodes ? toFloat(css(el.firstElementChild, "marginTop")) + toFloat(css(el.lastElementChild, "marginBottom")) : 0;
            var currentHeight = isVisible(el) ? height(el) + (inProgress ? 0 : inner) : 0;
            Transition.cancel(el);
            if (!isToggled(el)) {
                _toggle(el, true);
            }
            height(el, "");
            fastdom.flush();
            var endHeight = height(el) + (inProgress ? 0 : inner);
            height(el, currentHeight);
            return (show ? Transition.start(el, assign({}, initProps, {
                overflow: "hidden",
                height: endHeight
            }), Math.round(duration * (1 - currentHeight / endHeight)), transition$$1) : Transition.start(el, hideProps, Math.round(duration * (currentHeight / endHeight)), transition$$1).then(function () {
                return _toggle(el, false);
            })).then(function () {
                return css(el, initProps);
            });
        };
    }
    function toggleAnimation(ref) {
        var animation = ref.animation;
        var duration = ref.duration;
        var origin = ref.origin;
        var _toggle = ref._toggle;
        return function (el, show) {
            Animation.cancel(el);
            if (show) {
                _toggle(el, true);
                return Animation.in(el, animation[0], duration, origin);
            }
            return Animation.out(el, animation[1] || animation[0], duration, origin).then(function () {
                return _toggle(el, false);
            });
        };
    }
    var Accordion = {
        mixins: [Class, Togglable],
        props: {
            targets: String,
            active: null,
            collapsible: Boolean,
            multiple: Boolean,
            toggle: String,
            content: String,
            transition: String
        },
        data: {
            targets: "> *",
            active: false,
            animation: [true],
            collapsible: true,
            multiple: false,
            clsOpen: "uk-open",
            toggle: "> .uk-accordion-title",
            content: "> .uk-accordion-content",
            transition: "ease"
        },
        computed: {
            items: function (ref, $el) {
                var targets = ref.targets;
                return $$(targets, $el);
            }
        },
        events: [{
            name: "click",
            delegate: function () {
                return this.targets + " " + this.$props.toggle;
            },
            handler: function (e) {
                e.preventDefault();
                this.toggle(index($$(this.targets + " " + this.$props.toggle, this.$el), e.current));
            }
        }],
        connected: function () {
            if (this.active === false) {
                return;
            }
            var active = this.items[Number(this.active)];
            if (active && !hasClass(active, this.clsOpen)) {
                this.toggle(active, false);
            }
        },
        update: function () {
            var this$1 = this;
            this.items.forEach(function (el) {
                return this$1._toggle($(this$1.content, el), hasClass(el, this$1.clsOpen));
            });
            var active = !this.collapsible && !hasClass(this.items, this.clsOpen) && this.items[0];
            if (active) {
                this.toggle(active, false);
            }
        },
        methods: {
            toggle: function (item, animate$$1) {
                var this$1 = this;
                var index$$1 = getIndex(item, this.items);
                var active = filter(this.items, "." + this.clsOpen);
                item = this.items[index$$1];
                item && [item].concat(!this.multiple && !includes(active, item) && active || []).forEach(function (el) {
                    var isItem = el === item;
                    var state = isItem && !hasClass(el, this$1.clsOpen);
                    if (!state && isItem && !this$1.collapsible && active.length < 2) {
                        return;
                    }
                    toggleClass(el, this$1.clsOpen, state);
                    var content = el._wrapper ? el._wrapper.firstElementChild : $(this$1.content, el);
                    if (!el._wrapper) {
                        el._wrapper = wrapAll(content, "<div>");
                        attr(el._wrapper, "hidden", state ? "" : null);
                    }
                    this$1._toggle(content, true);
                    this$1.toggleElement(el._wrapper, state, animate$$1).then(function () {
                        if (hasClass(el, this$1.clsOpen) !== state) {
                            return;
                        }
                        if (!state) {
                            this$1._toggle(content, false);
                        }
                        el._wrapper = null;
                        unwrap(content);
                    });
                });
            }
        }
    };
    var Alert = {
        mixins: [Class, Togglable],
        args: "animation",
        props: {
            close: String
        },
        data: {
            animation: [true],
            selClose: ".uk-alert-close",
            duration: 150,
            hideProps: assign({
                opacity: 0
            }, Togglable.data.hideProps)
        },
        events: [{
            name: "click",
            delegate: function () {
                return this.selClose;
            },
            handler: function (e) {
                e.preventDefault();
                this.close();
            }
        }],
        methods: {
            close: function () {
                var this$1 = this;
                this.toggleElement(this.$el).then(function () {
                    return this$1.$destroy(true);
                });
            }
        }
    };
    function Core(UIkit) {
        ready(function () {
            UIkit.update();
            on(window, "load resize", function () {
                return UIkit.update(null, "resize");
            });
            on(document, "loadedmetadata load", function (ref) {
                var target = ref.target;
                return UIkit.update(target, "resize");
            }, true);
            var pending;
            on(window, "scroll", function (e) {
                if (pending) {
                    return;
                }
                pending = true;
                fastdom.write(function () {
                    return pending = false;
                });
                var target = e.target;
                UIkit.update(target.nodeType !== 1 ? document.body : target, e.type);
            }, {
                passive: true,
                capture: true
            });
            var started = 0;
            on(document, "animationstart", function (ref) {
                var target = ref.target;
                if ((css(target, "animationName") || "").match(/^uk-.*(left|right)/)) {
                    started++;
                    css(document.body, "overflowX", "hidden");
                    setTimeout(function () {
                        if (!--started) {
                            css(document.body, "overflowX", "");
                        }
                    }, toMs(css(target, "animationDuration")) + 100);
                }
            }, true);
        });
    }
    var Video = {
        args: "autoplay",
        props: {
            automute: Boolean,
            autoplay: Boolean
        },
        data: {
            automute: false,
            autoplay: true
        },
        computed: {
            inView: function (ref) {
                var autoplay = ref.autoplay;
                return autoplay === "inview";
            }
        },
        connected: function () {
            if (this.inView && !hasAttr(this.$el, "preload")) {
                this.$el.preload = "none";
            }
            this.player = new Player(this.$el);
            if (this.automute) {
                this.player.mute();
            }
        },
        update: {
            read: function () {
                return !this.player ? false : {
                    visible: isVisible(this.$el) && css(this.$el, "visibility") !== "hidden",
                    inView: this.inView && isInView(this.$el)
                };
            },
            write: function (ref) {
                var visible = ref.visible;
                var inView = ref.inView;
                if (!visible || this.inView && !inView) {
                    this.player.pause();
                } else if (this.autoplay === true || this.inView && inView) {
                    this.player.play();
                }
            },
            events: ["resize", "scroll"]
        }
    };
    var Cover = {
        mixins: [Class, Video],
        props: {
            width: Number,
            height: Number
        },
        data: {
            automute: true
        },
        update: {
            read: function () {
                var el = this.$el;
                if (!isVisible(el)) {
                    return false;
                }
                var ref = el.parentNode;
                var height$$1 = ref.offsetHeight;
                var width$$1 = ref.offsetWidth;
                return {
                    height: height$$1,
                    width: width$$1
                };
            },
            write: function (ref) {
                var height$$1 = ref.height;
                var width$$1 = ref.width;
                var el = this.$el;
                var elWidth = this.width || el.naturalWidth || el.videoWidth || el.clientWidth;
                var elHeight = this.height || el.naturalHeight || el.videoHeight || el.clientHeight;
                if (!elWidth || !elHeight) {
                    return;
                }
                css(el, Dimensions.cover({
                    width: elWidth,
                    height: elHeight
                }, {
                    width: width$$1 + (width$$1 % 2 ? 1 : 0),
                    height: height$$1 + (height$$1 % 2 ? 1 : 0)
                }));
            },
            events: ["resize"]
        }
    };
    var Position = {
        props: {
            pos: String,
            offset: null,
            flip: Boolean,
            clsPos: String
        },
        data: {
            pos: "bottom-" + (!isRtl ? "left" : "right"),
            flip: true,
            offset: false,
            clsPos: ""
        },
        computed: {
            pos: function (ref) {
                var pos = ref.pos;
                return (pos + (!includes(pos, "-") ? "-center" : "")).split("-");
            },
            dir: function () {
                return this.pos[0];
            },
            align: function () {
                return this.pos[1];
            }
        },
        methods: {
            positionAt: function (element, target, boundary) {
                removeClasses(element, this.clsPos + "-(top|bottom|left|right)(-[a-z]+)?");
                css(element, {
                    top: "",
                    left: ""
                });
                var node;
                var ref = this;
                var offset$$1 = ref.offset;
                var axis = this.getAxis();
                if (!isNumeric(offset$$1)) {
                    node = $(offset$$1);
                    offset$$1 = node ? offset(node)[axis === "x" ? "left" : "top"] - offset(target)[axis === "x" ? "right" : "bottom"] : 0;
                }
                var ref$1 = positionAt(element, target, axis === "x" ? flipPosition(this.dir) + " " + this.align : this.align + " " + flipPosition(this.dir), axis === "x" ? this.dir + " " + this.align : this.align + " " + this.dir, axis === "x" ? "" + (this.dir === "left" ? -offset$$1 : offset$$1) : " " + (this.dir === "top" ? -offset$$1 : offset$$1), null, this.flip, boundary).target;
                var x = ref$1.x;
                var y = ref$1.y;
                this.dir = axis === "x" ? x : y;
                this.align = axis === "x" ? y : x;
                toggleClass(element, this.clsPos + "-" + this.dir + "-" + this.align, this.offset === false);
            },
            getAxis: function () {
                return this.dir === "top" || this.dir === "bottom" ? "y" : "x";
            }
        }
    };
    var active;
    var Drop = {
        mixins: [Position, Togglable],
        args: "pos",
        props: {
            mode: "list",
            toggle: Boolean,
            boundary: Boolean,
            boundaryAlign: Boolean,
            delayShow: Number,
            delayHide: Number,
            clsDrop: String
        },
        data: {
            mode: ["click", "hover"],
            toggle: "- *",
            boundary: window,
            boundaryAlign: false,
            delayShow: 0,
            delayHide: 800,
            clsDrop: false,
            hoverIdle: 200,
            animation: ["uk-animation-fade"],
            cls: "uk-open"
        },
        computed: {
            boundary: function (ref, $el) {
                var boundary = ref.boundary;
                return query(boundary, $el);
            },
            clsDrop: function (ref) {
                var clsDrop = ref.clsDrop;
                return clsDrop || "uk-" + this.$options.name;
            },
            clsPos: function () {
                return this.clsDrop;
            }
        },
        created: function () {
            this.tracker = new MouseTracker();
        },
        connected: function () {
            addClass(this.$el, this.clsDrop);
            var ref = this.$props;
            var toggle = ref.toggle;
            this.toggle = toggle && this.$create("toggle", query(toggle, this.$el), {
                target: this.$el,
                mode: this.mode
            });
            !this.toggle && trigger(this.$el, "updatearia");
        },
        events: [{
            name: "click",
            delegate: function () {
                return "." + this.clsDrop + "-close";
            },
            handler: function (e) {
                e.preventDefault();
                this.hide(false);
            }
        }, {
            name: "click",
            delegate: function () {
                return 'a[href^="#"]';
            },
            handler: function (e) {
                if (e.defaultPrevented) {
                    return;
                }
                var id = e.target.hash;
                if (!id) {
                    e.preventDefault();
                }
                if (!id || !within(id, this.$el)) {
                    this.hide(false);
                }
            }
        }, {
            name: "beforescroll",
            handler: function () {
                this.hide(false);
            }
        }, {
            name: "toggle",
            self: true,
            handler: function (e, toggle) {
                e.preventDefault();
                if (this.isToggled()) {
                    this.hide(false);
                } else {
                    this.show(toggle, false);
                }
            }
        }, {
            name: pointerEnter,
            filter: function () {
                return includes(this.mode, "hover");
            },
            handler: function (e) {
                if (isTouch(e)) {
                    return;
                }
                if (active && active !== this && active.toggle && includes(active.toggle.mode, "hover") && !within(e.target, active.toggle.$el) && !pointInRect({
                    x: e.pageX,
                    y: e.pageY
                }, offset(active.$el))) {
                    active.hide(false);
                }
                e.preventDefault();
                this.show(this.toggle);
            }
        }, {
            name: "toggleshow",
            handler: function (e, toggle) {
                if (toggle && !includes(toggle.target, this.$el)) {
                    return;
                }
                e.preventDefault();
                this.show(toggle || this.toggle);
            }
        }, {
            name: "togglehide " + pointerLeave,
            handler: function (e, toggle) {
                if (isTouch(e) || toggle && !includes(toggle.target, this.$el)) {
                    return;
                }
                e.preventDefault();
                if (this.toggle && includes(this.toggle.mode, "hover")) {
                    this.hide();
                }
            }
        }, {
            name: "beforeshow",
            self: true,
            handler: function () {
                this.clearTimers();
                Animation.cancel(this.$el);
                this.position();
            }
        }, {
            name: "show",
            self: true,
            handler: function () {
                this.tracker.init();
                trigger(this.$el, "updatearia");
                registerEvent();
            }
        }, {
            name: "beforehide",
            self: true,
            handler: function () {
                this.clearTimers();
            }
        }, {
            name: "hide",
            handler: function (ref) {
                var target = ref.target;
                if (this.$el !== target) {
                    active = active === null && within(target, this.$el) && this.isToggled() ? this : active;
                    return;
                }
                active = this.isActive() ? null : active;
                trigger(this.$el, "updatearia");
                this.tracker.cancel();
            }
        }, {
            name: "updatearia",
            self: true,
            handler: function (e, toggle) {
                e.preventDefault();
                this.updateAria(this.$el);
                if (toggle || this.toggle) {
                    attr((toggle || this.toggle).$el, "aria-expanded", this.isToggled() ? "true" : "false");
                    toggleClass(this.toggle.$el, this.cls, this.isToggled());
                }
            }
        }],
        update: {
            write: function () {
                if (this.isToggled() && !Animation.inProgress(this.$el)) {
                    this.position();
                }
            },
            events: ["resize"]
        },
        methods: {
            show: function (toggle, delay) {
                var this$1 = this;
                if (delay === void 0) delay = true;
                var show = function () {
                    return !this$1.isToggled() && this$1.toggleElement(this$1.$el, true);
                };
                var tryShow = function () {
                    this$1.toggle = toggle || this$1.toggle;
                    this$1.clearTimers();
                    if (this$1.isActive()) {
                        return;
                    } else if (delay && active && active !== this$1 && active.isDelaying) {
                        this$1.showTimer = setTimeout(this$1.show, 10);
                        return;
                    } else if (this$1.isParentOf(active)) {
                        if (active.hideTimer) {
                            active.hide(false);
                        } else {
                            return;
                        }
                    } else if (active && this$1.isChildOf(active)) {
                        active.clearTimers();
                    } else if (active && !this$1.isChildOf(active) && !this$1.isParentOf(active)) {
                        var prev;
                        while (active && active !== prev && !this$1.isChildOf(active)) {
                            prev = active;
                            active.hide(false);
                        }
                    }
                    if (delay && this$1.delayShow) {
                        this$1.showTimer = setTimeout(show, this$1.delayShow);
                    } else {
                        show();
                    }
                    active = this$1;
                };
                if (toggle && this.toggle && toggle.$el !== this.toggle.$el) {
                    once(this.$el, "hide", tryShow);
                    this.hide(false);
                } else {
                    tryShow();
                }
            },
            hide: function (delay) {
                var this$1 = this;
                if (delay === void 0) delay = true;
                var hide = function () {
                    return this$1.toggleNow(this$1.$el, false);
                };
                this.clearTimers();
                this.isDelaying = this.tracker.movesTo(this.$el);
                if (delay && this.isDelaying) {
                    this.hideTimer = setTimeout(this.hide, this.hoverIdle);
                } else if (delay && this.delayHide) {
                    this.hideTimer = setTimeout(hide, this.delayHide);
                } else {
                    hide();
                }
            },
            clearTimers: function () {
                clearTimeout(this.showTimer);
                clearTimeout(this.hideTimer);
                this.showTimer = null;
                this.hideTimer = null;
                this.isDelaying = false;
            },
            isActive: function () {
                return active === this;
            },
            isChildOf: function (drop) {
                return drop && drop !== this && within(this.$el, drop.$el);
            },
            isParentOf: function (drop) {
                return drop && drop !== this && within(drop.$el, this.$el);
            },
            position: function () {
                removeClasses(this.$el, this.clsDrop + "-(stack|boundary)");
                css(this.$el, {
                    top: "",
                    left: "",
                    display: "block"
                });
                toggleClass(this.$el, this.clsDrop + "-boundary", this.boundaryAlign);
                var boundary = offset(this.boundary);
                var alignTo = this.boundaryAlign ? boundary : offset(this.toggle.$el);
                if (this.align === "justify") {
                    var prop = this.getAxis() === "y" ? "width" : "height";
                    css(this.$el, prop, alignTo[prop]);
                } else if (this.$el.offsetWidth > Math.max(boundary.right - alignTo.left, alignTo.right - boundary.left)) {
                    addClass(this.$el, this.clsDrop + "-stack");
                }
                this.positionAt(this.$el, this.boundaryAlign ? this.boundary : this.toggle.$el, this.boundary);
                css(this.$el, "display", "");
            }
        }
    };
    var registered;
    function registerEvent() {
        if (registered) {
            return;
        }
        registered = true;
        on(document, pointerUp, function (ref) {
            var target = ref.target;
            var defaultPrevented = ref.defaultPrevented;
            var prev;
            if (defaultPrevented) {
                return;
            }
            while (active && active !== prev && !within(target, active.$el) && !(active.toggle && within(target, active.toggle.$el))) {
                prev = active;
                active.hide(false);
            }
        });
    }
    var Dropdown = {
        extends: Drop
    };
    var FormCustom = {
        mixins: [Class],
        args: "target",
        props: {
            target: Boolean
        },
        data: {
            target: false
        },
        computed: {
            input: function (_, $el) {
                return $(selInput, $el);
            },
            state: function () {
                return this.input.nextElementSibling;
            },
            target: function (ref, $el) {
                var target = ref.target;
                return target && (target === true && this.input.parentNode === $el && this.input.nextElementSibling || query(target, $el));
            }
        },
        update: function () {
            var ref = this;
            var target = ref.target;
            var input = ref.input;
            if (!target) {
                return;
            }
            var option;
            var prop = isInput(target) ? "value" : "textContent";
            var prev = target[prop];
            var value = input.files && input.files[0] ? input.files[0].name : matches(input, "select") && (option = $$("option", input).filter(function (el) {
                return el.selected;
            })[0]) ? option.textContent : input.value;
            if (prev !== value) {
                target[prop] = value;
            }
        },
        events: {
            change: function () {
                this.$emit();
            }
        }
    };
    var Gif = {
        update: {
            read: function (data$$1) {
                var inview = isInView(this.$el);
                if (!inview || data$$1.isInView === inview) {
                    return false;
                }
                data$$1.isInView = inview;
            },
            write: function () {
                this.$el.src = this.$el.src;
            },
            events: ["scroll", "resize"]
        }
    };
    var Margin = {
        props: {
            margin: String,
            firstColumn: Boolean
        },
        data: {
            margin: "uk-margin-small-top",
            firstColumn: "uk-first-column"
        },
        update: {
            read: function (data$$1) {
                var items = this.$el.children;
                var rows = [[]];
                if (!items.length || !isVisible(this.$el)) {
                    return data$$1.rows = rows;
                }
                data$$1.rows = getRows(items);
                data$$1.stacks = !data$$1.rows.some(function (row) {
                    return row.length > 1;
                });
            },
            write: function (ref) {
                var this$1 = this;
                var rows = ref.rows;
                rows.forEach(function (row, i) {
                    return row.forEach(function (el, j) {
                        toggleClass(el, this$1.margin, i !== 0);
                        toggleClass(el, this$1.firstColumn, j === 0);
                    });
                });
            },
            events: ["resize"]
        }
    };
    function getRows(items) {
        var rows = [[]];
        for (var i = 0; i < items.length; i++) {
            var el = items[i];
            var dim = getOffset(el);
            if (!dim.height) {
                continue;
            }
            for (var j = rows.length - 1; j >= 0; j--) {
                var row = rows[j];
                if (!row[0]) {
                    row.push(el);
                    break;
                }
                var leftDim = void 0;
                if (row[0].offsetParent === el.offsetParent) {
                    leftDim = getOffset(row[0]);
                } else {
                    dim = getOffset(el, true);
                    leftDim = getOffset(row[0], true);
                }
                if (dim.top >= leftDim.bottom - 1) {
                    rows.push([el]);
                    break;
                }
                if (dim.bottom > leftDim.top) {
                    if (dim.left < leftDim.left && !isRtl) {
                        row.unshift(el);
                        break;
                    }
                    row.push(el);
                    break;
                }
                if (j === 0) {
                    rows.unshift([el]);
                    break;
                }
            }
        }
        return rows;
    }
    function getOffset(element, offset$$1) {
        var assign$$1;
        if (offset$$1 === void 0) offset$$1 = false;
        var offsetTop = element.offsetTop;
        var offsetLeft = element.offsetLeft;
        var offsetHeight = element.offsetHeight;
        if (offset$$1) {
            assign$$1 = offsetPosition(element), offsetTop = assign$$1[0], offsetLeft = assign$$1[1];
        }
        return {
            top: offsetTop,
            left: offsetLeft,
            height: offsetHeight,
            bottom: offsetTop + offsetHeight
        };
    }
    var Grid = {
        extends: Margin,
        mixins: [Class],
        name: "grid",
        props: {
            masonry: Boolean,
            parallax: Number
        },
        data: {
            margin: "uk-grid-margin",
            clsStack: "uk-grid-stack",
            masonry: false,
            parallax: 0
        },
        computed: {
            length: function (_, $el) {
                return $el.children.length;
            },
            parallax: function (ref) {
                var parallax = ref.parallax;
                return parallax && this.length ? Math.abs(parallax) : "";
            }
        },
        connected: function () {
            this.masonry && addClass(this.$el, "uk-flex-top uk-flex-wrap-top");
        },
        update: [{
            read: function (ref) {
                var rows = ref.rows;
                if (this.masonry || this.parallax) {
                    rows = rows.map(function (elements) {
                        return sortBy(elements, "offsetLeft");
                    });
                    if (isRtl) {
                        rows.map(function (row) {
                            return row.reverse();
                        });
                    }
                }
                var transitionInProgress = rows.some(function (elements) {
                    return elements.some(Transition.inProgress);
                });
                var translates = false;
                var elHeight = "";
                if (this.masonry && this.length) {
                    var height$$1 = 0;
                    translates = rows.reduce(function (translates, row, i) {
                        translates[i] = row.map(function (_, j) {
                            return i === 0 ? 0 : toFloat(translates[i - 1][j]) + (height$$1 - toFloat(rows[i - 1][j] && rows[i - 1][j].offsetHeight));
                        });
                        height$$1 = row.reduce(function (height$$1, el) {
                            return Math.max(height$$1, el.offsetHeight);
                        }, 0);
                        return translates;
                    }, []);
                    elHeight = maxColumnHeight(rows) + getMarginTop(this.$el, this.margin) * (rows.length - 1);
                }
                return {
                    rows: rows,
                    translates: translates,
                    height: !transitionInProgress ? elHeight : false
                };
            },
            write: function (ref) {
                var stacks = ref.stacks;
                var height$$1 = ref.height;
                toggleClass(this.$el, this.clsStack, stacks);
                css(this.$el, "paddingBottom", this.parallax);
                height$$1 !== false && css(this.$el, "height", height$$1);
            },
            events: ["resize"]
        }, {
            read: function (ref) {
                var height$$1 = ref.height;
                return {
                    scrolled: this.parallax ? scrolledOver(this.$el, height$$1 ? height$$1 - height(this.$el) : 0) * this.parallax : false
                };
            },
            write: function (ref) {
                var rows = ref.rows;
                var scrolled = ref.scrolled;
                var translates = ref.translates;
                if (scrolled === false && !translates) {
                    return;
                }
                rows.forEach(function (row, i) {
                    return row.forEach(function (el, j) {
                        return css(el, "transform", !scrolled && !translates ? "" : "translateY(" + ((translates && -translates[i][j]) + (scrolled ? j % 2 ? scrolled : scrolled / 8 : 0)) + "px)");
                    });
                });
            },
            events: ["scroll", "resize"]
        }]
    };
    function getMarginTop(root, cls) {
        var nodes = toNodes(root.children);
        var ref = nodes.filter(function (el) {
            return hasClass(el, cls);
        });
        var node = ref[0];
        return toFloat(node ? css(node, "marginTop") : css(nodes[0], "paddingLeft"));
    }
    function maxColumnHeight(rows) {
        return Math.max.apply(Math, rows.reduce(function (sum, row) {
            row.forEach(function (el, i) {
                return sum[i] = (sum[i] || 0) + el.offsetHeight;
            });
            return sum;
        }, []));
    }
    var FlexBug = isIE ? {
        data: {
            selMinHeight: false,
            forceHeight: false
        },
        computed: {
            elements: function (ref, $el) {
                var selMinHeight = ref.selMinHeight;
                return selMinHeight ? $$(selMinHeight, $el) : [$el];
            }
        },
        update: [{
            read: function () {
                css(this.elements, "height", "");
            },
            order: -5,
            events: ["resize"]
        }, {
            write: function () {
                var this$1 = this;
                this.elements.forEach(function (el) {
                    var height$$1 = toFloat(css(el, "minHeight"));
                    if (height$$1 && (this$1.forceHeight || Math.round(height$$1 + boxModelAdjust("height", el, "content-box")) >= el.offsetHeight)) {
                        css(el, "height", height$$1);
                    }
                });
            },
            order: 5,
            events: ["resize"]
        }]
    } : {};
    var HeightMatch = {
        mixins: [FlexBug],
        args: "target",
        props: {
            target: String,
            row: Boolean
        },
        data: {
            target: "> *",
            row: true,
            forceHeight: true
        },
        computed: {
            elements: function (ref, $el) {
                var target = ref.target;
                return $$(target, $el);
            }
        },
        update: {
            read: function () {
                return {
                    rows: (this.row ? getRows(this.elements) : [this.elements]).map(match)
                };
            },
            write: function (ref) {
                var rows = ref.rows;
                rows.forEach(function (ref) {
                    var heights = ref.heights;
                    var elements = ref.elements;
                    return elements.forEach(function (el, i) {
                        return css(el, "minHeight", heights[i]);
                    });
                });
            },
            events: ["resize"]
        }
    };
    function match(elements) {
        var assign$$1;
        if (elements.length < 2) {
            return {
                heights: [""],
                elements: elements
            };
        }
        var ref = getHeights(elements);
        var heights = ref.heights;
        var max = ref.max;
        var hasMinHeight = elements.some(function (el) {
            return el.style.minHeight;
        });
        var hasShrunk = elements.some(function (el, i) {
            return !el.style.minHeight && heights[i] < max;
        });
        if (hasMinHeight && hasShrunk) {
            css(elements, "minHeight", "");
            assign$$1 = getHeights(elements), heights = assign$$1.heights, max = assign$$1.max;
        }
        heights = elements.map(function (el, i) {
            return heights[i] === max && toFloat(el.style.minHeight).toFixed(2) !== max.toFixed(2) ? "" : max;
        });
        return {
            heights: heights,
            elements: elements
        };
    }
    function getHeights(elements) {
        var heights = elements.map(function (el) {
            return offset(el).height - boxModelAdjust("height", el, "content-box");
        });
        var max = Math.max.apply(null, heights);
        return {
            heights: heights,
            max: max
        };
    }
    var HeightViewport = {
        mixins: [FlexBug],
        props: {
            expand: Boolean,
            offsetTop: Boolean,
            offsetBottom: Boolean,
            minHeight: Number
        },
        data: {
            expand: false,
            offsetTop: false,
            offsetBottom: false,
            minHeight: 0
        },
        update: {
            read: function () {
                var minHeight = "";
                var box = boxModelAdjust("height", this.$el, "content-box");
                if (this.expand) {
                    minHeight = height(window) - (offsetHeight(document.documentElement) - offsetHeight(this.$el)) - box || "";
                } else {
                    minHeight = "calc(100vh";
                    if (this.offsetTop) {
                        var ref = offset(this.$el);
                        var top = ref.top;
                        minHeight += top < height(window) / 2 ? " - " + top + "px" : "";
                    }
                    if (this.offsetBottom === true) {
                        minHeight += " - " + offsetHeight(this.$el.nextElementSibling) + "px";
                    } else if (isNumeric(this.offsetBottom)) {
                        minHeight += " - " + this.offsetBottom + "vh";
                    } else if (this.offsetBottom && endsWith(this.offsetBottom, "px")) {
                        minHeight += " - " + toFloat(this.offsetBottom) + "px";
                    } else if (isString(this.offsetBottom)) {
                        minHeight += " - " + offsetHeight(query(this.offsetBottom, this.$el)) + "px";
                    }
                    minHeight += (box ? " - " + box + "px" : "") + ")";
                }
                return {
                    minHeight: minHeight
                };
            },
            write: function (ref) {
                var minHeight = ref.minHeight;
                css(this.$el, {
                    minHeight: minHeight
                });
                if (this.minHeight && toFloat(css(this.$el, "minHeight")) < this.minHeight) {
                    css(this.$el, "minHeight", this.minHeight);
                }
            },
            events: ["resize"]
        }
    };
    function offsetHeight(el) {
        return el && el.offsetHeight || 0;
    }
    var svgs = {};
    var SVG = {
        args: "src",
        props: {
            id: String,
            icon: String,
            src: String,
            style: String,
            width: Number,
            height: Number,
            ratio: Number,
            class: String
        },
        data: {
            ratio: 1,
            id: false,
            exclude: ["ratio", "src", "icon"],
            class: ""
        },
        connected: function () {
            var this$1 = this;
            var assign$$1;
            this.class += " uk-svg";
            if (!this.icon && includes(this.src, "#")) {
                var parts = this.src.split("#");
                if (parts.length > 1) {
                    assign$$1 = parts, this.src = assign$$1[0], this.icon = assign$$1[1];
                }
            }
            this.svg = this.getSvg().then(function (svg) {
                var el;
                if (isString(svg)) {
                    if (this$1.icon && includes(svg, "<symbol")) {
                        svg = parseSymbols(svg, this$1.icon) || svg;
                    }
                    el = $(svg.substr(svg.indexOf("<svg")));
                } else {
                    el = svg.cloneNode(true);
                }
                if (!el) {
                    return Promise.reject("SVG not found.");
                }
                var dimensions = attr(el, "viewBox");
                if (dimensions) {
                    dimensions = dimensions.split(" ");
                    this$1.width = this$1.$props.width || dimensions[2];
                    this$1.height = this$1.$props.height || dimensions[3];
                }
                this$1.width *= this$1.ratio;
                this$1.height *= this$1.ratio;
                for (var prop in this$1.$options.props) {
                    if (this$1[prop] && !includes(this$1.exclude, prop)) {
                        attr(el, prop, this$1[prop]);
                    }
                }
                if (!this$1.id) {
                    removeAttr(el, "id");
                }
                if (this$1.width && !this$1.height) {
                    removeAttr(el, "height");
                }
                if (this$1.height && !this$1.width) {
                    removeAttr(el, "width");
                }
                var src = this$1.icon || this$1.src;
                attr(el, "data-svg", src);
                var root = this$1.$el;
                if (isVoidElement(root) || root.tagName === "CANVAS") {
                    attr(root, {
                        hidden: true,
                        id: null
                    });
                    var next = root.nextElementSibling;
                    if (src === attr(next, "data-svg")) {
                        el = next;
                    } else {
                        after(root, el);
                    }
                } else {
                    var last = root.lastElementChild;
                    if (src === attr(last, "data-svg")) {
                        el = last;
                    } else {
                        append(root, el);
                    }
                }
                this$1.svgEl = el;
                return el;
            }, noop);
        },
        disconnected: function () {
            var this$1 = this;
            if (isVoidElement(this.$el)) {
                attr(this.$el, {
                    hidden: null,
                    id: this.id || null
                });
            }
            if (this.svg) {
                this.svg.then(function (svg) {
                    return (!this$1._connected || svg !== this$1.svgEl) && remove(svg);
                }, noop);
            }
            this.svg = this.svgEl = null;
        },
        methods: {
            getSvg: function () {
                var this$1 = this;
                if (!this.src) {
                    return Promise.reject();
                }
                if (svgs[this.src]) {
                    return svgs[this.src];
                }
                svgs[this.src] = new Promise(function (resolve, reject) {
                    if (startsWith(this$1.src, "data:")) {
                        resolve(decodeURIComponent(this$1.src.split(",")[1]));
                    } else {
                        ajax(this$1.src).then(function (xhr) {
                            return resolve(xhr.response);
                        }, function () {
                            return reject("SVG not found.");
                        });
                    }
                });
                return svgs[this.src];
            }
        }
    };
    var symbolRe = /<symbol(.*?id=(['"])(.*?)\2[^]*?<\/)symbol>/g;
    var symbols = {};
    function parseSymbols(svg, icon) {
        if (!symbols[svg]) {
            symbols[svg] = {};
            var match;
            while (match = symbolRe.exec(svg)) {
                symbols[svg][match[3]] = '<svg xmlns="http://www.w3.org/2000/svg"' + match[1] + "svg>";
            }
            symbolRe.lastIndex = 0;
        }
        return symbols[svg][icon];
    }
    var closeIcon = '<svg width="14" height="14" viewBox="0 0 14 14" xmlns="http://www.w3.org/2000/svg"><line fill="none" stroke="#000" stroke-width="1.1" x1="1" y1="1" x2="13" y2="13"/><line fill="none" stroke="#000" stroke-width="1.1" x1="13" y1="1" x2="1" y2="13"/></svg>';
    var closeLarge = '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><line fill="none" stroke="#000" stroke-width="1.4" x1="1" y1="1" x2="19" y2="19"/><line fill="none" stroke="#000" stroke-width="1.4" x1="19" y1="1" x2="1" y2="19"/></svg>';
    var marker = '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect x="9" y="4" width="1" height="11"/><rect x="4" y="9" width="11" height="1"/></svg>';
    var navbarToggleIcon = '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect y="9" width="20" height="2"/><rect y="3" width="20" height="2"/><rect y="15" width="20" height="2"/></svg>';
    var overlayIcon = '<svg width="40" height="40" viewBox="0 0 40 40" xmlns="http://www.w3.org/2000/svg"><rect x="19" y="0" width="1" height="40"/><rect x="0" y="19" width="40" height="1"/></svg>';
    var paginationNext = '<svg width="7" height="12" viewBox="0 0 7 12" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="1.2" points="1 1 6 6 1 11"/></svg>';
    var paginationPrevious = '<svg width="7" height="12" viewBox="0 0 7 12" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="1.2" points="6 1 1 6 6 11"/></svg>';
    var searchIcon = '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.1" cx="9" cy="9" r="7"/><path fill="none" stroke="#000" stroke-width="1.1" d="M14,14 L18,18 L14,14 Z"/></svg>';
    var searchLarge = '<svg width="40" height="40" viewBox="0 0 40 40" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.8" cx="17.5" cy="17.5" r="16.5"/><line fill="none" stroke="#000" stroke-width="1.8" x1="38" y1="39" x2="29" y2="30"/></svg>';
    var searchNavbar = '<svg width="24" height="24" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.1" cx="10.5" cy="10.5" r="9.5"/><line fill="none" stroke="#000" stroke-width="1.1" x1="23" y1="23" x2="17" y2="17"/></svg>';
    var slidenavNext = '<svg width="14px" height="24px" viewBox="0 0 14 24" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="1.4" points="1.225,23 12.775,12 1.225,1 "/></svg>';
    var slidenavNextLarge = '<svg width="25px" height="40px" viewBox="0 0 25 40" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="2" points="4.002,38.547 22.527,20.024 4,1.5 "/></svg>';
    var slidenavPrevious = '<svg width="14px" height="24px" viewBox="0 0 14 24" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="1.4" points="12.775,1 1.225,12 12.775,23 "/></svg>';
    var slidenavPreviousLarge = '<svg width="25px" height="40px" viewBox="0 0 25 40" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="2" points="20.527,1.5 2,20.024 20.525,38.547 "/></svg>';
    var spinner = '<svg width="30" height="30" viewBox="0 0 30 30" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" cx="15" cy="15" r="14"/></svg>';
    var totop = '<svg width="18" height="10" viewBox="0 0 18 10" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="1.2" points="1 9 9 1 17 9 "/></svg>';
    var parsed = {};
    var icons = {
        spinner: spinner,
        totop: totop,
        marker: marker,
        "close-icon": closeIcon,
        "close-large": closeLarge,
        "navbar-toggle-icon": navbarToggleIcon,
        "overlay-icon": overlayIcon,
        "pagination-next": paginationNext,
        "pagination-previous": paginationPrevious,
        "search-icon": searchIcon,
        "search-large": searchLarge,
        "search-navbar": searchNavbar,
        "slidenav-next": slidenavNext,
        "slidenav-next-large": slidenavNextLarge,
        "slidenav-previous": slidenavPrevious,
        "slidenav-previous-large": slidenavPreviousLarge
    };
    var Icon = {
        install: install,
        attrs: ["icon", "ratio"],
        mixins: [Class, SVG],
        args: "icon",
        props: ["icon"],
        data: {
            exclude: ["id", "style", "class", "src", "icon", "ratio"]
        },
        isIcon: true,
        connected: function () {
            addClass(this.$el, "uk-icon");
        },
        methods: {
            getSvg: function () {
                var icon = getIcon(applyRtl(this.icon));
                if (!icon) {
                    return Promise.reject("Icon not found.");
                }
                return Promise.resolve(icon);
            }
        }
    };
    var IconComponent = {
        extends: Icon,
        data: function (vm) {
            return {
                icon: hyphenate(vm.constructor.options.name)
            };
        }
    };
    var Slidenav = {
        extends: IconComponent,
        connected: function () {
            addClass(this.$el, "uk-slidenav");
        },
        computed: {
            icon: function (ref, $el) {
                var icon = ref.icon;
                return hasClass($el, "uk-slidenav-large") ? icon + "-large" : icon;
            }
        }
    };
    var Search = {
        extends: IconComponent,
        computed: {
            icon: function (ref, $el) {
                var icon = ref.icon;
                return hasClass($el, "uk-search-icon") && parents($el, ".uk-search-large").length ? "search-large" : parents($el, ".uk-search-navbar").length ? "search-navbar" : icon;
            }
        }
    };
    var Close = {
        extends: IconComponent,
        computed: {
            icon: function () {
                return "close-" + (hasClass(this.$el, "uk-close-large") ? "large" : "icon");
            }
        }
    };
    var Spinner = {
        extends: IconComponent,
        connected: function () {
            var this$1 = this;
            this.svg.then(function (svg) {
                return this$1.ratio !== 1 && css($("circle", svg), "strokeWidth", 1 / this$1.ratio);
            }, noop);
        }
    };
    function install(UIkit) {
        UIkit.icon.add = function (name, svg) {
            var obj;
            var added = isString(name) ? (obj = {}, obj[name] = svg, obj) : name;
            each(added, function (svg, name) {
                icons[name] = svg;
                delete parsed[name];
            });
            if (UIkit._initialized) {
                apply(document.body, function (el) {
                    return each(UIkit.getComponents(el), function (cmp) {
                        cmp.$options.isIcon && cmp.icon in added && cmp.$reset();
                    });
                });
            }
        };
    }
    function getIcon(icon) {
        if (!icons[icon]) {
            return null;
        }
        if (!parsed[icon]) {
            parsed[icon] = $(icons[icon].trim());
        }
        return parsed[icon];
    }
    function applyRtl(icon) {
        return isRtl ? swap(swap(icon, "left", "right"), "previous", "next") : icon;
    }
    var Img = {
        props: {
            dataSrc: String,
            dataSrcset: Boolean,
            sizes: String,
            width: Number,
            height: Number,
            offsetTop: String,
            offsetLeft: String,
            target: String
        },
        data: {
            dataSrc: "",
            dataSrcset: false,
            sizes: false,
            width: false,
            height: false,
            offsetTop: "50vh",
            offsetLeft: 0,
            target: false
        },
        computed: {
            cacheKey: function (ref) {
                var dataSrc = ref.dataSrc;
                return this.$name + "." + dataSrc;
            },
            width: function (ref) {
                var width$$1 = ref.width;
                var dataWidth = ref.dataWidth;
                return width$$1 || dataWidth;
            },
            height: function (ref) {
                var height$$1 = ref.height;
                var dataHeight = ref.dataHeight;
                return height$$1 || dataHeight;
            },
            sizes: function (ref) {
                var sizes = ref.sizes;
                var dataSizes = ref.dataSizes;
                return sizes || dataSizes;
            },
            isImg: function (_, $el) {
                return isImg($el);
            },
            target: {
                get: function (ref) {
                    var target = ref.target;
                    return [this.$el].concat(queryAll(target, this.$el));
                },
                watch: function () {
                    this.observe();
                }
            },
            offsetTop: function (ref) {
                var offsetTop = ref.offsetTop;
                return toPx(offsetTop, "height");
            },
            offsetLeft: function (ref) {
                var offsetLeft = ref.offsetLeft;
                return toPx(offsetLeft, "width");
            }
        },
        connected: function () {
            if (storage[this.cacheKey]) {
                setSrcAttrs(this.$el, storage[this.cacheKey] || this.dataSrc, this.dataSrcset, this.sizes);
            } else if (this.isImg && this.width && this.height) {
                setSrcAttrs(this.$el, getPlaceholderImage(this.width, this.height, this.sizes));
            }
            this.observer = new IntersectionObserver(this.load, {
                rootMargin: this.offsetTop + "px " + this.offsetLeft + "px"
            });
            requestAnimationFrame(this.observe);
        },
        disconnected: function () {
            this.observer.disconnect();
        },
        update: {
            read: function (ref) {
                var this$1 = this;
                var image = ref.image;
                if (!image && document.readyState === "complete") {
                    this.load(this.observer.takeRecords());
                }
                if (this.isImg) {
                    return false;
                }
                image && image.then(function (img) {
                    return img && img.currentSrc !== "" && setSrcAttrs(this$1.$el, currentSrc(img));
                });
            },
            write: function (data$$1) {
                if (this.dataSrcset && window.devicePixelRatio !== 1) {
                    var bgSize = css(this.$el, "backgroundSize");
                    if (bgSize.match(/^(auto\s?)+$/) || toFloat(bgSize) === data$$1.bgSize) {
                        data$$1.bgSize = getSourceSize(this.dataSrcset, this.sizes);
                        css(this.$el, "backgroundSize", data$$1.bgSize + "px");
                    }
                }
            },
            events: ["resize"]
        },
        methods: {
            load: function (entries) {
                var this$1 = this;
                if (!entries.some(function (entry) {
                    return entry.isIntersecting;
                })) {
                    return;
                }
                this._data.image = getImage(this.dataSrc, this.dataSrcset, this.sizes).then(function (img) {
                    setSrcAttrs(this$1.$el, currentSrc(img), img.srcset, img.sizes);
                    storage[this$1.cacheKey] = currentSrc(img);
                    return img;
                }, noop);
                this.observer.disconnect();
            },
            observe: function () {
                var this$1 = this;
                if (!this._data.image && this._connected) {
                    this.target.forEach(function (el) {
                        return this$1.observer.observe(el);
                    });
                }
            }
        }
    };
    function setSrcAttrs(el, src, srcset, sizes) {
        if (isImg(el)) {
            sizes && (el.sizes = sizes);
            srcset && (el.srcset = srcset);
            src && (el.src = src);
        } else if (src) {
            var change = !includes(el.style.backgroundImage, src);
            if (change) {
                css(el, "backgroundImage", "url(" + escape(src) + ")");
                trigger(el, createEvent("load", false));
            }
        }
    }
    function getPlaceholderImage(width$$1, height$$1, sizes) {
        var assign$$1;
        if (sizes) {
            assign$$1 = Dimensions.ratio({
                width: width$$1,
                height: height$$1
            }, "width", toPx(sizesToPixel(sizes))), width$$1 = assign$$1.width, height$$1 = assign$$1.height;
        }
        return 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="' + width$$1 + '" height="' + height$$1 + '"></svg>';
    }
    var sizesRe = /\s*(.*?)\s*(\w+|calc\(.*?\))\s*(?:,|$)/g;
    function sizesToPixel(sizes) {
        var matches$$1;
        sizesRe.lastIndex = 0;
        while (matches$$1 = sizesRe.exec(sizes)) {
            if (!matches$$1[1] || window.matchMedia(matches$$1[1]).matches) {
                matches$$1 = evaluateSize(matches$$1[2]);
                break;
            }
        }
        return matches$$1 || "100vw";
    }
    var sizeRe = /\d+(?:\w+|%)/g;
    var additionRe = /[+-]?(\d+)/g;
    function evaluateSize(size) {
        return startsWith(size, "calc") ? size.substring(5, size.length - 1).replace(sizeRe, function (size) {
            return toPx(size);
        }).replace(/ /g, "").match(additionRe).reduce(function (a, b) {
            return a + +b;
        }, 0) : size;
    }
    function toPx(value, property, element) {
        if (property === void 0) property = "width";
        if (element === void 0) element = window;
        return isNumeric(value) ? +value : endsWith(value, "vw") ? percent(element, "width", value) : endsWith(value, "vh") ? percent(element, "height", value) : endsWith(value, "%") ? percent(element, property, value) : toFloat(value);
    }
    var srcSetRe = /\s+\d+w\s*(?:,|$)/g;
    function getSourceSize(srcset, sizes) {
        var srcSize = toPx(sizesToPixel(sizes));
        var descriptors = (srcset.match(srcSetRe) || []).map(toFloat).sort(function (a, b) {
            return a - b;
        });
        return descriptors.filter(function (size) {
            return size >= srcSize;
        })[0] || descriptors.pop() || "";
    }
    var dimensions = {
        height: height,
        width: width
    };
    function percent(element, property, value) {
        return dimensions[property](element) * toFloat(value) / 100;
    }
    function isImg(el) {
        return el.tagName === "IMG";
    }
    function currentSrc(el) {
        return el.currentSrc || el.src;
    }
    var key = "__test__";
    var storage;
    try {
        storage = window.sessionStorage || {};
        storage[key] = 1;
        delete storage[key];
    } catch (e) {
        storage = {};
    }
    var Media = {
        props: {
            media: Boolean
        },
        data: {
            media: false
        },
        computed: {
            matchMedia: function () {
                var media = toMedia(this.media);
                return !media || window.matchMedia(media).matches;
            }
        }
    };
    function toMedia(value) {
        if (isString(value)) {
            if (value[0] === "@") {
                var name = "breakpoint-" + value.substr(1);
                value = toFloat(getCssVar(name));
            } else if (isNaN(value)) {
                return value;
            }
        }
        return value && !isNaN(value) ? "(min-width: " + value + "px)" : false;
    }
    var Leader = {
        mixins: [Class, Media],
        props: {
            fill: String
        },
        data: {
            fill: "",
            clsWrapper: "uk-leader-fill",
            clsHide: "uk-leader-hide",
            attrFill: "data-fill"
        },
        computed: {
            fill: function (ref) {
                var fill = ref.fill;
                return fill || getCssVar("leader-fill-content");
            }
        },
        connected: function () {
            var assign$$1;
            assign$$1 = wrapInner(this.$el, '<span class="' + this.clsWrapper + '">'), this.wrapper = assign$$1[0];
        },
        disconnected: function () {
            unwrap(this.wrapper.childNodes);
        },
        update: {
            read: function (ref) {
                var changed = ref.changed;
                var width$$1 = ref.width;
                var prev = width$$1;
                width$$1 = Math.floor(this.$el.offsetWidth / 2);
                return {
                    width: width$$1,
                    changed: changed || prev !== width$$1,
                    hide: !this.matchMedia
                };
            },
            write: function (data$$1) {
                toggleClass(this.wrapper, this.clsHide, data$$1.hide);
                if (data$$1.changed) {
                    data$$1.changed = false;
                    attr(this.wrapper, this.attrFill, new Array(data$$1.width).join(this.fill));
                }
            },
            events: ["resize"]
        }
    };
    var Container = {
        props: {
            container: Boolean
        },
        data: {
            container: true
        },
        computed: {
            container: function (ref) {
                var container = ref.container;
                return container === true && this.$container || container && $(container);
            }
        }
    };
    var active$1;
    var Modal = {
        mixins: [Class, Container, Togglable],
        props: {
            selPanel: String,
            selClose: String,
            escClose: Boolean,
            bgClose: Boolean,
            stack: Boolean
        },
        data: {
            cls: "uk-open",
            escClose: true,
            bgClose: true,
            overlay: true,
            stack: false
        },
        computed: {
            panel: function (ref, $el) {
                var selPanel = ref.selPanel;
                return $(selPanel, $el);
            },
            transitionElement: function () {
                return this.panel;
            },
            bgClose: function (ref) {
                var bgClose = ref.bgClose;
                return bgClose && this.panel;
            }
        },
        beforeDisconnect: function () {
            if (this.isToggled()) {
                this.toggleNow(this.$el, false);
            }
        },
        events: [{
            name: "click",
            delegate: function () {
                return this.selClose;
            },
            handler: function (e) {
                e.preventDefault();
                this.hide();
            }
        }, {
            name: "toggle",
            self: true,
            handler: function (e) {
                if (e.defaultPrevented) {
                    return;
                }
                e.preventDefault();
                this.toggle();
            }
        }, {
            name: "beforeshow",
            self: true,
            handler: function (e) {
                var prev = active$1 && active$1 !== this && active$1;
                active$1 = this;
                if (prev) {
                    if (this.stack) {
                        this.prev = prev;
                    } else {
                        active$1 = prev;
                        if (prev.isToggled()) {
                            prev.hide().then(this.show);
                        } else {
                            once(prev.$el, "beforeshow hidden", this.show, false, function (ref) {
                                var target = ref.target;
                                var type = ref.type;
                                return type === "hidden" && target === prev.$el;
                            });
                        }
                        e.preventDefault();
                    }
                    return;
                }
                registerEvents();
            }
        }, {
            name: "show",
            self: true,
            handler: function () {
                if (!hasClass(document.documentElement, this.clsPage)) {
                    this.scrollbarWidth = width(window) - width(document);
                    css(document.body, "overflowY", this.scrollbarWidth && this.overlay ? "scroll" : "");
                }
                addClass(document.documentElement, this.clsPage);
            }
        }, {
            name: "hide",
            self: true,
            handler: function () {
                if (!active$1 || active$1 === this && !this.prev) {
                    deregisterEvents();
                }
            }
        }, {
            name: "hidden",
            self: true,
            handler: function () {
                var found;
                var ref = this;
                var prev = ref.prev;
                active$1 = active$1 && active$1 !== this && active$1 || prev;
                if (!active$1) {
                    css(document.body, "overflowY", "");
                } else {
                    while (prev) {
                        if (prev.clsPage === this.clsPage) {
                            found = true;
                            break;
                        }
                        prev = prev.prev;
                    }
                }
                if (!found) {
                    removeClass(document.documentElement, this.clsPage);
                }
            }
        }],
        methods: {
            toggle: function () {
                return this.isToggled() ? this.hide() : this.show();
            },
            show: function () {
                var this$1 = this;
                if (this.isToggled()) {
                    return Promise.resolve();
                }
                if (this.container && this.$el.parentNode !== this.container) {
                    append(this.container, this.$el);
                    return new Promise(function (resolve) {
                        return requestAnimationFrame(function () {
                            return this$1.show().then(resolve);
                        });
                    });
                }
                return this.toggleElement(this.$el, true, animate$1(this));
            },
            hide: function () {
                return this.isToggled() ? this.toggleElement(this.$el, false, animate$1(this)) : Promise.resolve();
            },
            getActive: function () {
                return active$1;
            }
        }
    };
    var events;
    function registerEvents() {
        if (events) {
            return;
        }
        events = [on(document, pointerUp, function (ref) {
            var target = ref.target;
            var defaultPrevented = ref.defaultPrevented;
            if (active$1 && active$1.bgClose && !defaultPrevented && (!active$1.overlay || within(target, active$1.$el)) && !within(target, active$1.panel)) {
                active$1.hide();
            }
        }), on(document, "keydown", function (e) {
            if (e.keyCode === 27 && active$1 && active$1.escClose) {
                e.preventDefault();
                active$1.hide();
            }
        })];
    }
    function deregisterEvents() {
        events && events.forEach(function (unbind) {
            return unbind();
        });
        events = null;
    }
    function animate$1(ref) {
        var transitionElement = ref.transitionElement;
        var _toggle = ref._toggle;
        return function (el, show) {
            return new Promise(function (resolve, reject) {
                return once(el, "show hide", function () {
                    el._reject && el._reject();
                    el._reject = reject;
                    _toggle(el, show);
                    if (toMs(css(transitionElement, "transitionDuration"))) {
                        once(transitionElement, "transitionend", resolve, false, function (e) {
                            return e.target === transitionElement;
                        });
                    } else {
                        resolve();
                    }
                });
            });
        };
    }
    var Modal$1 = {
        install: install$1,
        mixins: [Modal],
        data: {
            clsPage: "uk-modal-page",
            selPanel: ".uk-modal-dialog",
            selClose: ".uk-modal-close, .uk-modal-close-default, .uk-modal-close-outside, .uk-modal-close-full"
        },
        events: [{
            name: "show",
            self: true,
            handler: function () {
                if (hasClass(this.panel, "uk-margin-auto-vertical")) {
                    addClass(this.$el, "uk-flex");
                } else {
                    css(this.$el, "display", "block");
                }
                height(this.$el);
            }
        }, {
            name: "hidden",
            self: true,
            handler: function () {
                css(this.$el, "display", "");
                removeClass(this.$el, "uk-flex");
            }
        }]
    };
    function install$1(UIkit) {
        UIkit.modal.dialog = function (content, options) {
            var dialog = UIkit.modal(' <div class="uk-modal"> <div class="uk-modal-dialog">' + content + "</div> </div> ", options);
            dialog.show();
            on(dialog.$el, "hidden", function (ref) {
                var target = ref.target;
                var currentTarget = ref.currentTarget;
                if (target === currentTarget) {
                    Promise.resolve(function () {
                        return dialog.$destroy(true);
                    });
                }
            });
            return dialog;
        };
        UIkit.modal.alert = function (message, options) {
            options = assign({
                bgClose: false,
                escClose: false,
                labels: UIkit.modal.labels
            }, options);
            return new Promise(function (resolve) {
                return on(UIkit.modal.dialog(' <div class="uk-modal-body">' + (isString(message) ? message : html(message)) + '</div> <div class="uk-modal-footer uk-text-right"> <button class="uk-button uk-button-primary uk-modal-close" autofocus>' + options.labels.ok + "</button> </div> ", options).$el, "hide", resolve);
            });
        };
        UIkit.modal.confirm = function (message, options) {
            options = assign({
                bgClose: false,
                escClose: true,
                labels: UIkit.modal.labels
            }, options);
            return new Promise(function (resolve, reject) {
                var confirm = UIkit.modal.dialog(' <form> <div class="uk-modal-body">' + (isString(message) ? message : html(message)) + '</div> <div class="uk-modal-footer uk-text-right"> <button class="uk-button uk-button-default uk-modal-close" type="button">' + options.labels.cancel + '</button> <button class="uk-button uk-button-primary" autofocus>' + options.labels.ok + "</button> </div> </form> ", options);
                var resolved = false;
                on(confirm.$el, "submit", "form", function (e) {
                    e.preventDefault();
                    resolve();
                    resolved = true;
                    confirm.hide();
                });
                on(confirm.$el, "hide", function () {
                    if (!resolved) {
                        reject();
                    }
                });
            });
        };
        UIkit.modal.prompt = function (message, value, options) {
            options = assign({
                bgClose: false,
                escClose: true,
                labels: UIkit.modal.labels
            }, options);
            return new Promise(function (resolve) {
                var prompt = UIkit.modal.dialog(' <form class="uk-form-stacked"> <div class="uk-modal-body"> <label>' + (isString(message) ? message : html(message)) + '</label> <input class="uk-input" autofocus> </div> <div class="uk-modal-footer uk-text-right"> <button class="uk-button uk-button-default uk-modal-close" type="button">' + options.labels.cancel + '</button> <button class="uk-button uk-button-primary">' + options.labels.ok + "</button> </div> </form> ", options), input = $("input", prompt.$el);
                input.value = value;
                var resolved = false;
                on(prompt.$el, "submit", "form", function (e) {
                    e.preventDefault();
                    resolve(input.value);
                    resolved = true;
                    prompt.hide();
                });
                on(prompt.$el, "hide", function () {
                    if (!resolved) {
                        resolve(null);
                    }
                });
            });
        };
        UIkit.modal.labels = {
            ok: "Ok",
            cancel: "Cancel"
        };
    }
    var Nav = {
        extends: Accordion,
        data: {
            targets: "> .uk-parent",
            toggle: "> a",
            content: "> ul"
        }
    };
    var Navbar = {
        mixins: [Class, FlexBug],
        props: {
            dropdown: String,
            mode: "list",
            align: String,
            offset: Number,
            boundary: Boolean,
            boundaryAlign: Boolean,
            clsDrop: String,
            delayShow: Number,
            delayHide: Number,
            dropbar: Boolean,
            dropbarMode: String,
            dropbarAnchor: Boolean,
            duration: Number
        },
        data: {
            dropdown: ".uk-navbar-nav > li",
            align: !isRtl ? "left" : "right",
            clsDrop: "uk-navbar-dropdown",
            mode: undefined,
            offset: undefined,
            delayShow: undefined,
            delayHide: undefined,
            boundaryAlign: undefined,
            flip: "x",
            boundary: true,
            dropbar: false,
            dropbarMode: "slide",
            dropbarAnchor: false,
            duration: 200,
            forceHeight: true,
            selMinHeight: ".uk-navbar-nav > li > a, .uk-navbar-item, .uk-navbar-toggle"
        },
        computed: {
            boundary: function (ref, $el) {
                var boundary = ref.boundary;
                var boundaryAlign = ref.boundaryAlign;
                return boundary === true || boundaryAlign ? $el : boundary;
            },
            dropbarAnchor: function (ref, $el) {
                var dropbarAnchor = ref.dropbarAnchor;
                return query(dropbarAnchor, $el);
            },
            pos: function (ref) {
                var align = ref.align;
                return "bottom-" + align;
            },
            dropdowns: function (ref, $el) {
                var dropdown = ref.dropdown;
                var clsDrop = ref.clsDrop;
                return $$(dropdown + " ." + clsDrop, $el);
            }
        },
        beforeConnect: function () {
            var ref = this.$props;
            var dropbar = ref.dropbar;
            this.dropbar = dropbar && (query(dropbar, this.$el) || $("+ .uk-navbar-dropbar", this.$el) || $("<div></div>"));
            if (this.dropbar) {
                addClass(this.dropbar, "uk-navbar-dropbar");
                if (this.dropbarMode === "slide") {
                    addClass(this.dropbar, "uk-navbar-dropbar-slide");
                }
            }
        },
        disconnected: function () {
            this.dropbar && remove(this.dropbar);
        },
        update: function () {
            var this$1 = this;
            this.$create("drop", this.dropdowns.filter(function (el) {
                return !this$1.getDropdown(el);
            }), assign({}, this.$props, {
                boundary: this.boundary,
                pos: this.pos,
                offset: this.dropbar || this.offset
            }));
        },
        events: [{
            name: "mouseover",
            delegate: function () {
                return this.dropdown;
            },
            handler: function (ref) {
                var current = ref.current;
                var active = this.getActive();
                if (active && active.toggle && !within(active.toggle.$el, current) && !active.tracker.movesTo(active.$el)) {
                    active.hide(false);
                }
            }
        }, {
            name: "mouseleave",
            el: function () {
                return this.dropbar;
            },
            handler: function () {
                var active = this.getActive();
                if (active && !matches(this.dropbar, ":hover")) {
                    active.hide();
                }
            }
        }, {
            name: "beforeshow",
            capture: true,
            filter: function () {
                return this.dropbar;
            },
            handler: function () {
                if (!this.dropbar.parentNode) {
                    after(this.dropbarAnchor || this.$el, this.dropbar);
                }
            }
        }, {
            name: "show",
            capture: true,
            filter: function () {
                return this.dropbar;
            },
            handler: function (_, drop) {
                var $el = drop.$el;
                var dir = drop.dir;
                this.clsDrop && addClass($el, this.clsDrop + "-dropbar");
                if (dir === "bottom") {
                    this.transitionTo($el.offsetHeight + toFloat(css($el, "marginTop")) + toFloat(css($el, "marginBottom")), $el);
                }
            }
        }, {
            name: "beforehide",
            filter: function () {
                return this.dropbar;
            },
            handler: function (e, ref) {
                var $el = ref.$el;
                var active = this.getActive();
                if (matches(this.dropbar, ":hover") && active && active.$el === $el) {
                    e.preventDefault();
                }
            }
        }, {
            name: "hide",
            filter: function () {
                return this.dropbar;
            },
            handler: function (_, ref) {
                var $el = ref.$el;
                var active = this.getActive();
                if (!active || active && active.$el === $el) {
                    this.transitionTo(0);
                }
            }
        }],
        methods: {
            getActive: function () {
                var ref = this.dropdowns.map(this.getDropdown).filter(function (drop) {
                    return drop && drop.isActive();
                });
                var active = ref[0];
                return active && includes(active.mode, "hover") && within(active.toggle.$el, this.$el) && active;
            },
            transitionTo: function (newHeight, el) {
                var this$1 = this;
                var ref = this;
                var dropbar = ref.dropbar;
                var oldHeight = isVisible(dropbar) ? height(dropbar) : 0;
                el = oldHeight < newHeight && el;
                css(el, "clip", "rect(0," + el.offsetWidth + "px," + oldHeight + "px,0)");
                height(dropbar, oldHeight);
                Transition.cancel([el, dropbar]);
                return Promise.all([Transition.start(dropbar, {
                    height: newHeight
                }, this.duration), Transition.start(el, {
                    clip: "rect(0," + el.offsetWidth + "px," + newHeight + "px,0)"
                }, this.duration)]).catch(noop).then(function () {
                    css(el, {
                        clip: ""
                    });
                    this$1.$update(dropbar);
                });
            },
            getDropdown: function (el) {
                return this.$getComponent(el, "drop") || this.$getComponent(el, "dropdown");
            }
        }
    };
    var Offcanvas = {
        mixins: [Modal],
        args: "mode",
        props: {
            mode: String,
            flip: Boolean,
            overlay: Boolean
        },
        data: {
            mode: "slide",
            flip: false,
            overlay: false,
            clsPage: "uk-offcanvas-page",
            clsContainer: "uk-offcanvas-container",
            selPanel: ".uk-offcanvas-bar",
            clsFlip: "uk-offcanvas-flip",
            clsContainerAnimation: "uk-offcanvas-container-animation",
            clsSidebarAnimation: "uk-offcanvas-bar-animation",
            clsMode: "uk-offcanvas",
            clsOverlay: "uk-offcanvas-overlay",
            selClose: ".uk-offcanvas-close"
        },
        computed: {
            clsFlip: function (ref) {
                var flip = ref.flip;
                var clsFlip = ref.clsFlip;
                return flip ? clsFlip : "";
            },
            clsOverlay: function (ref) {
                var overlay = ref.overlay;
                var clsOverlay = ref.clsOverlay;
                return overlay ? clsOverlay : "";
            },
            clsMode: function (ref) {
                var mode = ref.mode;
                var clsMode = ref.clsMode;
                return clsMode + "-" + mode;
            },
            clsSidebarAnimation: function (ref) {
                var mode = ref.mode;
                var clsSidebarAnimation = ref.clsSidebarAnimation;
                return mode === "none" || mode === "reveal" ? "" : clsSidebarAnimation;
            },
            clsContainerAnimation: function (ref) {
                var mode = ref.mode;
                var clsContainerAnimation = ref.clsContainerAnimation;
                return mode !== "push" && mode !== "reveal" ? "" : clsContainerAnimation;
            },
            transitionElement: function (ref) {
                var mode = ref.mode;
                return mode === "reveal" ? this.panel.parentNode : this.panel;
            }
        },
        events: [{
            name: "click",
            delegate: function () {
                return 'a[href^="#"]';
            },
            handler: function (ref) {
                var current = ref.current;
                if (current.hash && $(current.hash, document.body)) {
                    this.hide();
                }
            }
        }, {
            name: "touchstart",
            el: function () {
                return this.panel;
            },
            handler: function (ref) {
                var targetTouches = ref.targetTouches;
                if (targetTouches.length === 1) {
                    this.clientY = targetTouches[0].clientY;
                }
            }
        }, {
            name: "touchmove",
            self: true,
            passive: false,
            filter: function () {
                return this.overlay;
            },
            handler: function (e) {
                e.preventDefault();
            }
        }, {
            name: "touchmove",
            passive: false,
            el: function () {
                return this.panel;
            },
            handler: function (e) {
                if (e.targetTouches.length !== 1) {
                    return;
                }
                var clientY = event.targetTouches[0].clientY - this.clientY;
                var ref = this.panel;
                var scrollTop$$1 = ref.scrollTop;
                var scrollHeight = ref.scrollHeight;
                var clientHeight = ref.clientHeight;
                if (clientHeight >= scrollHeight || scrollTop$$1 === 0 && clientY > 0 || scrollHeight - scrollTop$$1 <= clientHeight && clientY < 0) {
                    e.preventDefault();
                }
            }
        }, {
            name: "show",
            self: true,
            handler: function () {
                if (this.mode === "reveal" && !hasClass(this.panel.parentNode, this.clsMode)) {
                    wrapAll(this.panel, "<div>");
                    addClass(this.panel.parentNode, this.clsMode);
                }
                css(document.documentElement, "overflowY", this.overlay ? "hidden" : "");
                addClass(document.body, this.clsContainer, this.clsFlip);
                css(this.$el, "display", "block");
                addClass(this.$el, this.clsOverlay);
                addClass(this.panel, this.clsSidebarAnimation, this.mode !== "reveal" ? this.clsMode : "");
                height(document.body);
                addClass(document.body, this.clsContainerAnimation);
                this.clsContainerAnimation && suppressUserScale();
            }
        }, {
            name: "hide",
            self: true,
            handler: function () {
                removeClass(document.body, this.clsContainerAnimation);
                var active = this.getActive();
                if (this.mode === "none" || active && active !== this && active !== this.prev) {
                    trigger(this.panel, "transitionend");
                }
            }
        }, {
            name: "hidden",
            self: true,
            handler: function () {
                this.clsContainerAnimation && resumeUserScale();
                if (this.mode === "reveal") {
                    unwrap(this.panel);
                }
                removeClass(this.panel, this.clsSidebarAnimation, this.clsMode);
                removeClass(this.$el, this.clsOverlay);
                css(this.$el, "display", "");
                removeClass(document.body, this.clsContainer, this.clsFlip);
                css(document.documentElement, "overflowY", "");
            }
        }, {
            name: "swipeLeft swipeRight",
            handler: function (e) {
                if (this.isToggled() && isTouch(e) && e.type === "swipeLeft" ^ this.flip) {
                    this.hide();
                }
            }
        }]
    };
    function suppressUserScale() {
        getViewport().content += ",user-scalable=0";
    }
    function resumeUserScale() {
        var viewport = getViewport();
        viewport.content = viewport.content.replace(/,user-scalable=0$/, "");
    }
    function getViewport() {
        return $('meta[name="viewport"]', document.head) || append(document.head, '<meta name="viewport">');
    }
    var OverflowAuto = {
        mixins: [Class],
        props: {
            selContainer: String,
            selContent: String
        },
        data: {
            selContainer: ".uk-modal",
            selContent: ".uk-modal-dialog"
        },
        computed: {
            container: function (ref, $el) {
                var selContainer = ref.selContainer;
                return closest($el, selContainer);
            },
            content: function (ref, $el) {
                var selContent = ref.selContent;
                return closest($el, selContent);
            }
        },
        connected: function () {
            css(this.$el, "minHeight", 150);
        },
        update: {
            read: function () {
                if (!this.content || !this.container) {
                    return false;
                }
                return {
                    current: toFloat(css(this.$el, "maxHeight")),
                    max: Math.max(150, height(this.container) - (offset(this.content).height - height(this.$el)))
                };
            },
            write: function (ref) {
                var current = ref.current;
                var max = ref.max;
                css(this.$el, "maxHeight", max);
                if (Math.round(current) !== Math.round(max)) {
                    trigger(this.$el, "resize");
                }
            },
            events: ["resize"]
        }
    };
    var Responsive = {
        props: ["width", "height"],
        connected: function () {
            addClass(this.$el, "uk-responsive-width");
        },
        update: {
            read: function () {
                return isVisible(this.$el) && this.width && this.height ? {
                    width: width(this.$el.parentNode),
                    height: this.height
                } : false;
            },
            write: function (dim) {
                height(this.$el, Dimensions.contain({
                    height: this.height,
                    width: this.width
                }, dim).height);
            },
            events: ["resize"]
        }
    };
    var Scroll = {
        props: {
            duration: Number,
            offset: Number
        },
        data: {
            duration: 1e3,
            offset: 0
        },
        methods: {
            scrollTo: function (el) {
                var this$1 = this;
                el = el && $(el) || document.body;
                var docHeight = height(document);
                var winHeight = height(window);
                var target = offset(el).top - this.offset;
                if (target + winHeight > docHeight) {
                    target = docHeight - winHeight;
                }
                if (!trigger(this.$el, "beforescroll", [this, el])) {
                    return;
                }
                var start = Date.now();
                var startY = window.pageYOffset;
                var step = function () {
                    var currentY = startY + (target - startY) * ease(clamp((Date.now() - start) / this$1.duration));
                    scrollTop(window, currentY);
                    if (currentY !== target) {
                        requestAnimationFrame(step);
                    } else {
                        trigger(this$1.$el, "scrolled", [this$1, el]);
                    }
                };
                step();
            }
        },
        events: {
            click: function (e) {
                if (e.defaultPrevented) {
                    return;
                }
                e.preventDefault();
                this.scrollTo(escape(decodeURIComponent(this.$el.hash)).substr(1));
            }
        }
    };
    function ease(k) {
        return .5 * (1 - Math.cos(Math.PI * k));
    }
    var Scrollspy = {
        args: "cls",
        props: {
            cls: "list",
            target: String,
            hidden: Boolean,
            offsetTop: Number,
            offsetLeft: Number,
            repeat: Boolean,
            delay: Number
        },
        data: function () {
            return {
                cls: [],
                target: false,
                hidden: true,
                offsetTop: 0,
                offsetLeft: 0,
                repeat: false,
                delay: 0,
                inViewClass: "uk-scrollspy-inview"
            };
        },
        computed: {
            elements: function (ref, $el) {
                var target = ref.target;
                return target ? $$(target, $el) : [$el];
            }
        },
        update: [{
            write: function () {
                if (this.hidden) {
                    css(filter(this.elements, ":not(." + this.inViewClass + ")"), "visibility", "hidden");
                }
            }
        }, {
            read: function (els) {
                var this$1 = this;
                if (!els.update) {
                    return;
                }
                this.elements.forEach(function (el, i) {
                    var elData = els[i];
                    if (!elData || elData.el !== el) {
                        var cls = data(el, "uk-scrollspy-class");
                        elData = {
                            el: el,
                            toggles: cls && cls.split(",") || this$1.cls
                        };
                    }
                    elData.show = isInView(el, this$1.offsetTop, this$1.offsetLeft);
                    els[i] = elData;
                });
            },
            write: function (els) {
                var this$1 = this;
                if (!els.update) {
                    this.$emit();
                    return els.update = true;
                }
                this.elements.forEach(function (el, i) {
                    var elData = els[i];
                    var cls = elData.toggles[i] || elData.toggles[0];
                    if (elData.show && !elData.inview && !elData.queued) {
                        var show = function () {
                            css(el, "visibility", "");
                            addClass(el, this$1.inViewClass);
                            toggleClass(el, cls);
                            trigger(el, "inview");
                            this$1.$update(el);
                            elData.inview = true;
                            elData.abort && elData.abort();
                        };
                        if (this$1.delay) {
                            elData.queued = true;
                            els.promise = (els.promise || Promise.resolve()).then(function () {
                                return !elData.inview && new Promise(function (resolve) {
                                    var timer = setTimeout(function () {
                                        show();
                                        resolve();
                                    }, els.promise || this$1.elements.length === 1 ? this$1.delay : 0);
                                    elData.abort = function () {
                                        clearTimeout(timer);
                                        resolve();
                                        elData.queued = false;
                                    };
                                });
                            });
                        } else {
                            show();
                        }
                    } else if (!elData.show && (elData.inview || elData.queued) && this$1.repeat) {
                        elData.abort && elData.abort();
                        if (!elData.inview) {
                            return;
                        }
                        css(el, "visibility", this$1.hidden ? "hidden" : "");
                        removeClass(el, this$1.inViewClass);
                        toggleClass(el, cls);
                        trigger(el, "outview");
                        this$1.$update(el);
                        elData.inview = false;
                    }
                });
            },
            events: ["scroll", "resize"]
        }]
    };
    var ScrollspyNav = {
        props: {
            cls: String,
            closest: String,
            scroll: Boolean,
            overflow: Boolean,
            offset: Number
        },
        data: {
            cls: "uk-active",
            closest: false,
            scroll: false,
            overflow: true,
            offset: 0
        },
        computed: {
            links: function (_, $el) {
                return $$('a[href^="#"]', $el).filter(function (el) {
                    return el.hash;
                });
            },
            elements: function (ref) {
                var selector = ref.closest;
                return closest(this.links, selector || "*");
            },
            targets: function () {
                return $$(this.links.map(function (el) {
                    return el.hash;
                }).join(","));
            }
        },
        update: [{
            read: function () {
                if (this.scroll) {
                    this.$create("scroll", this.links, {
                        offset: this.offset || 0
                    });
                }
            }
        }, {
            read: function (data$$1) {
                var this$1 = this;
                var scroll = window.pageYOffset + this.offset + 1;
                var max = height(document) - height(window) + this.offset;
                data$$1.active = false;
                this.targets.every(function (el, i) {
                    var ref = offset(el);
                    var top = ref.top;
                    var last = i + 1 === this$1.targets.length;
                    if (!this$1.overflow && (i === 0 && top > scroll || last && top + el.offsetTop < scroll)) {
                        return false;
                    }
                    if (!last && offset(this$1.targets[i + 1]).top <= scroll) {
                        return true;
                    }
                    if (scroll >= max) {
                        for (var j = this$1.targets.length - 1; j > i; j--) {
                            if (isInView(this$1.targets[j])) {
                                el = this$1.targets[j];
                                break;
                            }
                        }
                    }
                    return !(data$$1.active = $(filter(this$1.links, '[href="#' + el.id + '"]')));
                });
            },
            write: function (ref) {
                var active = ref.active;
                this.links.forEach(function (el) {
                    return el.blur();
                });
                removeClass(this.elements, this.cls);
                if (active) {
                    trigger(this.$el, "active", [active, addClass(this.closest ? closest(active, this.closest) : active, this.cls)]);
                }
            },
            events: ["scroll", "resize"]
        }]
    };
    var Sticky = {
        mixins: [Class, Media],
        props: {
            top: null,
            bottom: Boolean,
            offset: Number,
            animation: String,
            clsActive: String,
            clsInactive: String,
            clsFixed: String,
            clsBelow: String,
            selTarget: String,
            widthElement: Boolean,
            showOnUp: Boolean,
            targetOffset: Number
        },
        data: {
            top: 0,
            bottom: false,
            offset: 0,
            animation: "",
            clsActive: "uk-active",
            clsInactive: "",
            clsFixed: "uk-sticky-fixed",
            clsBelow: "uk-sticky-below",
            selTarget: "",
            widthElement: false,
            showOnUp: false,
            targetOffset: false
        },
        computed: {
            selTarget: function (ref, $el) {
                var selTarget = ref.selTarget;
                return selTarget && $(selTarget, $el) || $el;
            },
            widthElement: function (ref, $el) {
                var widthElement = ref.widthElement;
                return query(widthElement, $el) || this.placeholder;
            },
            isActive: {
                get: function () {
                    return hasClass(this.selTarget, this.clsActive);
                },
                set: function (value) {
                    if (value && !this.isActive) {
                        replaceClass(this.selTarget, this.clsInactive, this.clsActive);
                        trigger(this.$el, "active");
                    } else if (!value && !hasClass(this.selTarget, this.clsInactive)) {
                        replaceClass(this.selTarget, this.clsActive, this.clsInactive);
                        trigger(this.$el, "inactive");
                    }
                }
            }
        },
        connected: function () {
            this.placeholder = $("+ .uk-sticky-placeholder", this.$el) || $('<div class="uk-sticky-placeholder"></div>');
            this.isFixed = false;
            this.isActive = false;
        },
        disconnected: function () {
            if (this.isFixed) {
                this.hide();
                removeClass(this.selTarget, this.clsInactive);
            }
            remove(this.placeholder);
            this.placeholder = null;
            this.widthElement = null;
        },
        events: [{
            name: "load hashchange popstate",
            el: window,
            handler: function () {
                var this$1 = this;
                if (!(this.targetOffset !== false && location.hash && window.pageYOffset > 0)) {
                    return;
                }
                var target = $(location.hash);
                if (target) {
                    fastdom.read(function () {
                        var ref = offset(target);
                        var top = ref.top;
                        var elTop = offset(this$1.$el).top;
                        var elHeight = this$1.$el.offsetHeight;
                        if (this$1.isFixed && elTop + elHeight >= top && elTop <= top + target.offsetHeight) {
                            scrollTop(window, top - elHeight - (isNumeric(this$1.targetOffset) ? this$1.targetOffset : 0) - this$1.offset);
                        }
                    });
                }
            }
        }],
        update: [{
            read: function (ref, type) {
                var height$$1 = ref.height;
                if (this.isActive && type !== "update") {
                    this.hide();
                    height$$1 = this.$el.offsetHeight;
                    this.show();
                }
                height$$1 = !this.isActive ? this.$el.offsetHeight : height$$1;
                this.topOffset = offset(this.isFixed ? this.placeholder : this.$el).top;
                this.bottomOffset = this.topOffset + height$$1;
                var bottom = parseProp("bottom", this);
                this.top = Math.max(toFloat(parseProp("top", this)), this.topOffset) - this.offset;
                this.bottom = bottom && bottom - height$$1;
                this.inactive = !this.matchMedia;
                return {
                    lastScroll: false,
                    height: height$$1,
                    margins: css(this.$el, ["marginTop", "marginBottom", "marginLeft", "marginRight"])
                };
            },
            write: function (ref) {
                var height$$1 = ref.height;
                var margins = ref.margins;
                var ref$1 = this;
                var placeholder = ref$1.placeholder;
                css(placeholder, assign({
                    height: height$$1
                }, margins));
                if (!within(placeholder, document)) {
                    after(this.$el, placeholder);
                    attr(placeholder, "hidden", "");
                }
                this.isActive = this.isActive;
            },
            events: ["resize"]
        }, {
            read: function (ref) {
                var scroll = ref.scroll;
                if (scroll === void 0) scroll = 0;
                this.width = (isVisible(this.widthElement) ? this.widthElement : this.$el).offsetWidth;
                this.scroll = window.pageYOffset;
                return {
                    dir: scroll <= this.scroll ? "down" : "up",
                    scroll: this.scroll,
                    visible: isVisible(this.$el),
                    top: offsetPosition(this.placeholder)[0]
                };
            },
            write: function (data$$1, type) {
                var this$1 = this;
                var initTimestamp = data$$1.initTimestamp;
                if (initTimestamp === void 0) initTimestamp = 0;
                var dir = data$$1.dir;
                var lastDir = data$$1.lastDir;
                var lastScroll = data$$1.lastScroll;
                var scroll = data$$1.scroll;
                var top = data$$1.top;
                var visible = data$$1.visible;
                var now = performance.now();
                data$$1.lastScroll = scroll;
                if (scroll < 0 || scroll === lastScroll || !visible || this.disabled || this.showOnUp && type !== "scroll") {
                    return;
                }
                if (now - initTimestamp > 300 || dir !== lastDir) {
                    data$$1.initScroll = scroll;
                    data$$1.initTimestamp = now;
                }
                data$$1.lastDir = dir;
                if (this.showOnUp && Math.abs(data$$1.initScroll - scroll) <= 30 && Math.abs(lastScroll - scroll) <= 10) {
                    return;
                }
                if (this.inactive || scroll < this.top || this.showOnUp && (scroll <= this.top || dir === "down" || dir === "up" && !this.isFixed && scroll <= this.bottomOffset)) {
                    if (!this.isFixed) {
                        if (Animation.inProgress(this.$el) && top > scroll) {
                            Animation.cancel(this.$el);
                            this.hide();
                        }
                        return;
                    }
                    this.isFixed = false;
                    if (this.animation && scroll > this.topOffset) {
                        Animation.cancel(this.$el);
                        Animation.out(this.$el, this.animation).then(function () {
                            return this$1.hide();
                        }, noop);
                    } else {
                        this.hide();
                    }
                } else if (this.isFixed) {
                    this.update();
                } else if (this.animation) {
                    Animation.cancel(this.$el);
                    this.show();
                    Animation.in(this.$el, this.animation).catch(noop);
                } else {
                    this.show();
                }
            },
            events: ["resize", "scroll"]
        }],
        methods: {
            show: function () {
                this.isFixed = true;
                this.update();
                attr(this.placeholder, "hidden", null);
            },
            hide: function () {
                this.isActive = false;
                removeClass(this.$el, this.clsFixed, this.clsBelow);
                css(this.$el, {
                    position: "",
                    top: "",
                    width: ""
                });
                attr(this.placeholder, "hidden", "");
            },
            update: function () {
                var active = this.top !== 0 || this.scroll > this.top;
                var top = Math.max(0, this.offset);
                if (this.bottom && this.scroll > this.bottom - this.offset) {
                    top = this.bottom - this.scroll;
                }
                css(this.$el, {
                    position: "fixed",
                    top: top + "px",
                    width: this.width
                });
                this.isActive = active;
                toggleClass(this.$el, this.clsBelow, this.scroll > this.bottomOffset);
                addClass(this.$el, this.clsFixed);
            }
        }
    };
    function parseProp(prop, ref) {
        var $props = ref.$props;
        var $el = ref.$el;
        var propOffset = ref[prop + "Offset"];
        var value = $props[prop];
        if (!value) {
            return;
        }
        if (isNumeric(value)) {
            return propOffset + toFloat(value);
        } else if (isString(value) && value.match(/^-?\d+vh$/)) {
            return height(window) * toFloat(value) / 100;
        } else {
            var el = value === true ? $el.parentNode : query(value, $el);
            if (el) {
                return offset(el).top + el.offsetHeight;
            }
        }
    }
    var Switcher = {
        mixins: [Togglable],
        args: "connect",
        props: {
            connect: String,
            toggle: String,
            active: Number,
            swiping: Boolean
        },
        data: {
            connect: "~.uk-switcher",
            toggle: "> * > :first-child",
            active: 0,
            swiping: true,
            cls: "uk-active",
            clsContainer: "uk-switcher",
            attrItem: "uk-switcher-item",
            queued: true
        },
        computed: {
            connects: function (ref, $el) {
                var connect = ref.connect;
                return queryAll(connect, $el);
            },
            toggles: function (ref, $el) {
                var toggle = ref.toggle;
                return $$(toggle, $el);
            }
        },
        events: [{
            name: "click",
            delegate: function () {
                return this.toggle + ":not(.uk-disabled)";
            },
            handler: function (e) {
                e.preventDefault();
                this.show(toNodes(this.$el.children).filter(function (el) {
                    return within(e.current, el);
                })[0]);
            }
        }, {
            name: "click",
            el: function () {
                return this.connects;
            },
            delegate: function () {
                return "[" + this.attrItem + "],[data-" + this.attrItem + "]";
            },
            handler: function (e) {
                e.preventDefault();
                this.show(data(e.current, this.attrItem));
            }
        }, {
            name: "swipeRight swipeLeft",
            filter: function () {
                return this.swiping;
            },
            el: function () {
                return this.connects;
            },
            handler: function (e) {
                if (!isTouch(e)) {
                    return;
                }
                e.preventDefault();
                if (!window.getSelection().toString()) {
                    this.show(e.type === "swipeLeft" ? "next" : "previous");
                }
            }
        }],
        update: function () {
            var this$1 = this;
            this.connects.forEach(function (list) {
                return this$1.updateAria(list.children);
            });
            var ref = this.$el;
            var children = ref.children;
            this.show(filter(children, "." + this.cls)[0] || children[this.active] || children[0]);
        },
        methods: {
            index: function () {
                return !!this.connects.length && index(filter(this.connects[0].children, "." + this.cls)[0]);
            },
            show: function (item) {
                var this$1 = this;
                var ref = this.$el;
                var children = ref.children;
                var length = children.length;
                var prev = this.index();
                var hasPrev = prev >= 0;
                var dir = item === "previous" ? -1 : 1;
                var toggle, active, next = getIndex(item, children, prev);
                for (var i = 0; i < length; i++, next = (next + dir + length) % length) {
                    if (!matches(this.toggles[next], ".uk-disabled *, .uk-disabled, [disabled]")) {
                        toggle = this.toggles[next];
                        active = children[next];
                        break;
                    }
                }
                if (!active || prev >= 0 && hasClass(active, this.cls) || prev === next) {
                    return;
                }
                removeClass(children, this.cls);
                addClass(active, this.cls);
                attr(this.toggles, "aria-expanded", false);
                attr(toggle, "aria-expanded", true);
                this.connects.forEach(function (list) {
                    if (!hasPrev) {
                        this$1.toggleNow(list.children[next]);
                    } else {
                        this$1.toggleElement([list.children[prev], list.children[next]]);
                    }
                });
            }
        }
    };
    var Tab = {
        mixins: [Class],
        extends: Switcher,
        props: {
            media: Boolean
        },
        data: {
            media: 960,
            attrItem: "uk-tab-item"
        },
        connected: function () {
            var cls = hasClass(this.$el, "uk-tab-left") ? "uk-tab-left" : hasClass(this.$el, "uk-tab-right") ? "uk-tab-right" : false;
            if (cls) {
                this.$create("toggle", this.$el, {
                    cls: cls,
                    mode: "media",
                    media: this.media
                });
            }
        }
    };
    var Toggle = {
        mixins: [Media, Togglable],
        args: "target",
        props: {
            href: String,
            target: null,
            mode: "list"
        },
        data: {
            href: false,
            target: false,
            mode: "click",
            queued: true
        },
        computed: {
            target: function (ref, $el) {
                var href = ref.href;
                var target = ref.target;
                target = queryAll(target || href, $el);
                return target.length && target || [$el];
            }
        },
        connected: function () {
            trigger(this.target, "updatearia", [this]);
        },
        events: [{
            name: pointerEnter + " " + pointerLeave,
            filter: function () {
                return includes(this.mode, "hover");
            },
            handler: function (e) {
                if (!isTouch(e)) {
                    this.toggle("toggle" + (e.type === pointerEnter ? "show" : "hide"));
                }
            }
        }, {
            name: "click",
            filter: function () {
                return includes(this.mode, "click") || hasTouch && includes(this.mode, "hover");
            },
            handler: function (e) {
                if (!isTouch(e) && !includes(this.mode, "click")) {
                    return;
                }
                var link;
                if (closest(e.target, 'a[href="#"], a[href=""], button') || (link = closest(e.target, "a[href]")) && (this.cls || !isVisible(this.target) || link.hash && matches(this.target, link.hash))) {
                    e.preventDefault();
                }
                this.toggle();
            }
        }],
        update: {
            write: function () {
                if (!includes(this.mode, "media") || !this.media) {
                    return;
                }
                var toggled = this.isToggled(this.target);
                if (this.matchMedia ? !toggled : toggled) {
                    this.toggle();
                }
            },
            events: ["resize"]
        },
        methods: {
            toggle: function (type) {
                if (trigger(this.target, type || "toggle", [this])) {
                    this.toggleElement(this.target);
                }
            }
        }
    };
    function core(UIkit) {
        UIkit.component("accordion", Accordion);
        UIkit.component("alert", Alert);
        UIkit.component("cover", Cover);
        UIkit.component("drop", Drop);
        UIkit.component("dropdown", Dropdown);
        UIkit.component("formCustom", FormCustom);
        UIkit.component("gif", Gif);
        UIkit.component("grid", Grid);
        UIkit.component("heightMatch", HeightMatch);
        UIkit.component("heightViewport", HeightViewport);
        UIkit.component("icon", Icon);
        UIkit.component("img", Img);
        UIkit.component("leader", Leader);
        UIkit.component("margin", Margin);
        UIkit.component("modal", Modal$1);
        UIkit.component("nav", Nav);
        UIkit.component("navbar", Navbar);
        UIkit.component("offcanvas", Offcanvas);
        UIkit.component("overflowAuto", OverflowAuto);
        UIkit.component("responsive", Responsive);
        UIkit.component("scroll", Scroll);
        UIkit.component("scrollspy", Scrollspy);
        UIkit.component("scrollspyNav", ScrollspyNav);
        UIkit.component("sticky", Sticky);
        UIkit.component("svg", SVG);
        UIkit.component("switcher", Switcher);
        UIkit.component("tab", Tab);
        UIkit.component("toggle", Toggle);
        UIkit.component("video", Video);
        UIkit.component("close", Close);
        UIkit.component("marker", IconComponent);
        UIkit.component("navbarToggleIcon", IconComponent);
        UIkit.component("overlayIcon", IconComponent);
        UIkit.component("paginationNext", IconComponent);
        UIkit.component("paginationPrevious", IconComponent);
        UIkit.component("searchIcon", Search);
        UIkit.component("slidenavNext", Slidenav);
        UIkit.component("slidenavPrevious", Slidenav);
        UIkit.component("spinner", Spinner);
        UIkit.component("totop", IconComponent);
        UIkit.use(Core);
    }
    UIkit.version = "3.0.3";
    core(UIkit);
    var Countdown = {
        mixins: [Class],
        props: {
            date: String,
            clsWrapper: String
        },
        data: {
            date: "",
            clsWrapper: ".uk-countdown-%unit%"
        },
        computed: {
            date: function (ref) {
                var date = ref.date;
                return Date.parse(date);
            },
            days: function (ref, $el) {
                var clsWrapper = ref.clsWrapper;
                return $(clsWrapper.replace("%unit%", "days"), $el);
            },
            hours: function (ref, $el) {
                var clsWrapper = ref.clsWrapper;
                return $(clsWrapper.replace("%unit%", "hours"), $el);
            },
            minutes: function (ref, $el) {
                var clsWrapper = ref.clsWrapper;
                return $(clsWrapper.replace("%unit%", "minutes"), $el);
            },
            seconds: function (ref, $el) {
                var clsWrapper = ref.clsWrapper;
                return $(clsWrapper.replace("%unit%", "seconds"), $el);
            },
            units: function () {
                var this$1 = this;
                return ["days", "hours", "minutes", "seconds"].filter(function (unit) {
                    return this$1[unit];
                });
            }
        },
        connected: function () {
            this.start();
        },
        disconnected: function () {
            var this$1 = this;
            this.stop();
            this.units.forEach(function (unit) {
                return empty(this$1[unit]);
            });
        },
        events: [{
            name: "visibilitychange",
            el: document,
            handler: function () {
                if (document.hidden) {
                    this.stop();
                } else {
                    this.start();
                }
            }
        }],
        update: {
            write: function () {
                var this$1 = this;
                var timespan = getTimeSpan(this.date);
                if (timespan.total <= 0) {
                    this.stop();
                    timespan.days = timespan.hours = timespan.minutes = timespan.seconds = 0;
                }
                this.units.forEach(function (unit) {
                    var digits = String(Math.floor(timespan[unit]));
                    digits = digits.length < 2 ? "0" + digits : digits;
                    var el = this$1[unit];
                    if (el.textContent !== digits) {
                        digits = digits.split("");
                        if (digits.length !== el.children.length) {
                            html(el, digits.map(function () {
                                return "<span></span>";
                            }).join(""));
                        }
                        digits.forEach(function (digit, i) {
                            return el.children[i].textContent = digit;
                        });
                    }
                });
            }
        },
        methods: {
            start: function () {
                var this$1 = this;
                this.stop();
                if (this.date && this.units.length) {
                    this.$emit();
                    this.timer = setInterval(function () {
                        return this$1.$emit();
                    }, 1e3);
                }
            },
            stop: function () {
                if (this.timer) {
                    clearInterval(this.timer);
                    this.timer = null;
                }
            }
        }
    };
    function getTimeSpan(date) {
        var total = date - Date.now();
        return {
            total: total,
            seconds: total / 1e3 % 60,
            minutes: total / 1e3 / 60 % 60,
            hours: total / 1e3 / 60 / 60 % 24,
            days: total / 1e3 / 60 / 60 / 24
        };
    }
    var targetClass = "uk-animation-target";
    var Animate = {
        props: {
            animation: Number
        },
        data: {
            animation: 150
        },
        computed: {
            target: function () {
                return this.$el;
            }
        },
        methods: {
            animate: function (action) {
                var this$1 = this;
                addStyle();
                var children = toNodes(this.target.children);
                var propsFrom = children.map(function (el) {
                    return getProps(el, true);
                });
                var oldHeight = height(this.target);
                var oldScrollY = window.pageYOffset;
                action();
                Transition.cancel(this.target);
                children.forEach(Transition.cancel);
                reset(this.target);
                this.$update(this.target);
                fastdom.flush();
                var newHeight = height(this.target);
                children = children.concat(toNodes(this.target.children).filter(function (el) {
                    return !includes(children, el);
                }));
                var propsTo = children.map(function (el, i) {
                    return el.parentNode && i in propsFrom ? propsFrom[i] ? isVisible(el) ? getPositionWithMargin(el) : {
                        opacity: 0
                    } : {
                        opacity: isVisible(el) ? 1 : 0
                    } : false;
                });
                propsFrom = propsTo.map(function (props, i) {
                    var from = children[i].parentNode === this$1.target ? propsFrom[i] || getProps(children[i]) : false;
                    if (from) {
                        if (!props) {
                            delete from.opacity;
                        } else if (!("opacity" in props)) {
                            var opacity = from.opacity;
                            if (opacity % 1) {
                                props.opacity = 1;
                            } else {
                                delete from.opacity;
                            }
                        }
                    }
                    return from;
                });
                addClass(this.target, targetClass);
                children.forEach(function (el, i) {
                    return propsFrom[i] && css(el, propsFrom[i]);
                });
                css(this.target, "height", oldHeight);
                scrollTop(window, oldScrollY);
                return Promise.all(children.map(function (el, i) {
                    return propsFrom[i] && propsTo[i] ? Transition.start(el, propsTo[i], this$1.animation, "ease") : Promise.resolve();
                }).concat(Transition.start(this.target, {
                    height: newHeight
                }, this.animation, "ease"))).then(function () {
                    children.forEach(function (el, i) {
                        return css(el, {
                            display: propsTo[i].opacity === 0 ? "none" : "",
                            zIndex: ""
                        });
                    });
                    reset(this$1.target);
                    this$1.$update(this$1.target);
                    fastdom.flush();
                }, noop);
            }
        }
    };
    function getProps(el, opacity) {
        var zIndex = css(el, "zIndex");
        return isVisible(el) ? assign({
            display: "",
            opacity: opacity ? css(el, "opacity") : "0",
            pointerEvents: "none",
            position: "absolute",
            zIndex: zIndex === "auto" ? index(el) : zIndex
        }, getPositionWithMargin(el)) : false;
    }
    function reset(el) {
        css(el.children, {
            height: "",
            left: "",
            opacity: "",
            pointerEvents: "",
            position: "",
            top: "",
            width: ""
        });
        removeClass(el, targetClass);
        css(el, "height", "");
    }
    function getPositionWithMargin(el) {
        var ref = el.getBoundingClientRect();
        var height$$1 = ref.height;
        var width$$1 = ref.width;
        var ref$1 = position(el);
        var top = ref$1.top;
        var left = ref$1.left;
        top += toFloat(css(el, "marginTop"));
        return {
            top: top,
            left: left,
            height: height$$1,
            width: width$$1
        };
    }
    var style$1;
    function addStyle() {
        if (!style$1) {
            style$1 = append(document.head, "<style>").sheet;
            style$1.insertRule("." + targetClass + " > * {\n                    margin-top: 0 !important;\n                    transform: none !important;\n                }", 0);
        }
    }
    var Filter = {
        mixins: [Animate],
        args: "target",
        props: {
            target: Boolean,
            selActive: Boolean
        },
        data: {
            target: null,
            selActive: false,
            attrItem: "uk-filter-control",
            cls: "uk-active",
            animation: 250
        },
        computed: {
            toggles: {
                get: function (ref, $el) {
                    var attrItem = ref.attrItem;
                    return $$("[" + this.attrItem + "],[data-" + this.attrItem + "]", $el);
                },
                watch: function () {
                    this.setState(this.getState(), false);
                }
            },
            target: function (ref, $el) {
                var target = ref.target;
                return $(target, $el);
            },
            children: {
                get: function () {
                    return toNodes(this.target.children);
                },
                watch: function (list, old) {
                    if (!isEqualList(list, old)) {
                        this.updateState();
                    }
                }
            }
        },
        events: [{
            name: "click",
            delegate: function () {
                return "[" + this.attrItem + "],[data-" + this.attrItem + "]";
            },
            handler: function (e) {
                e.preventDefault();
                this.apply(e.current);
            }
        }],
        connected: function () {
            var this$1 = this;
            if (this.selActive === false) {
                return;
            }
            var actives = $$(this.selActive, this.$el);
            this.toggles.forEach(function (el) {
                return toggleClass(el, this$1.cls, includes(actives, el));
            });
        },
        methods: {
            apply: function (el) {
                this.setState(mergeState(el, this.attrItem, this.getState()));
            },
            getState: function () {
                var this$1 = this;
                return this.toggles.filter(function (item) {
                    return hasClass(item, this$1.cls);
                }).reduce(function (state, el) {
                    return mergeState(el, this$1.attrItem, state);
                }, {
                    filter: {
                        "": ""
                    },
                    sort: []
                });
            },
            setState: function (state, animate$$1) {
                var this$1 = this;
                if (animate$$1 === void 0) animate$$1 = true;
                state = assign({
                    filter: {
                        "": ""
                    },
                    sort: []
                }, state);
                trigger(this.$el, "beforeFilter", [this, state]);
                var ref = this;
                var children = ref.children;
                this.toggles.forEach(function (el) {
                    return toggleClass(el, this$1.cls, matchFilter(el, this$1.attrItem, state));
                });
                var apply$$1 = function () {
                    var selector = getSelector(state);
                    children.forEach(function (el) {
                        return css(el, "display", selector && !matches(el, selector) ? "none" : "");
                    });
                    var ref = state.sort;
                    var sort = ref[0];
                    var order = ref[1];
                    if (sort) {
                        var sorted = sortItems(children, sort, order);
                        if (!isEqual(sorted, children)) {
                            sorted.forEach(function (el) {
                                return append(this$1.target, el);
                            });
                        }
                    }
                };
                if (animate$$1) {
                    this.animate(apply$$1).then(function () {
                        return trigger(this$1.$el, "afterFilter", [this$1]);
                    });
                } else {
                    apply$$1();
                    trigger(this.$el, "afterFilter", [this]);
                }
            },
            updateState: function () {
                this.setState(this.getState(), false);
            }
        }
    };
    function getFilter(el, attr$$1) {
        return parseOptions(data(el, attr$$1), ["filter"]);
    }
    function mergeState(el, attr$$1, state) {
        toNodes(el).forEach(function (el) {
            var filterBy = getFilter(el, attr$$1);
            var filter$$1 = filterBy.filter;
            var group = filterBy.group;
            var sort = filterBy.sort;
            var order = filterBy.order;
            if (order === void 0) order = "asc";
            if (filter$$1 || isUndefined(sort)) {
                if (group) {
                    delete state.filter[""];
                    state.filter[group] = filter$$1;
                } else {
                    state.filter = {
                        "": filter$$1 || ""
                    };
                }
            }
            if (!isUndefined(sort)) {
                state.sort = [sort, order];
            }
        });
        return state;
    }
    function matchFilter(el, attr$$1, ref) {
        var stateFilter = ref.filter;
        if (stateFilter === void 0) stateFilter = {
            "": ""
        };
        var ref_sort = ref.sort;
        var stateSort = ref_sort[0];
        var stateOrder = ref_sort[1];
        var ref$1 = getFilter(el, attr$$1);
        var filter$$1 = ref$1.filter;
        var group = ref$1.group;
        if (group === void 0) group = "";
        var sort = ref$1.sort;
        var order = ref$1.order;
        if (order === void 0) order = "asc";
        filter$$1 = isUndefined(sort) ? filter$$1 || "" : filter$$1;
        sort = isUndefined(filter$$1) ? sort || "" : sort;
        return (isUndefined(filter$$1) || group in stateFilter && filter$$1 === stateFilter[group]) && (isUndefined(sort) || stateSort === sort && stateOrder === order);
    }
    function isEqualList(listA, listB) {
        return listA.length === listB.length && listA.every(function (el) {
            return ~listB.indexOf(el);
        });
    }
    function getSelector(ref) {
        var filter$$1 = ref.filter;
        var selector = "";
        each(filter$$1, function (value) {
            return selector += value || "";
        });
        return selector;
    }
    function sortItems(nodes, sort, order) {
        return assign([], nodes).sort(function (a, b) {
            return data(a, sort).localeCompare(data(b, sort), undefined, {
                numeric: true
            }) * (order === "asc" || -1);
        });
    }
    var Animations = {
        slide: {
            show: function (dir) {
                return [{
                    transform: translate(dir * -100)
                }, {
                    transform: translate()
                }];
            },
            percent: function (current) {
                return translated(current);
            },
            translate: function (percent, dir) {
                return [{
                    transform: translate(dir * -100 * percent)
                }, {
                    transform: translate(dir * 100 * (1 - percent))
                }];
            }
        }
    };
    function translated(el) {
        return Math.abs(css(el, "transform").split(",")[4] / el.offsetWidth) || 0;
    }
    function translate(value, unit) {
        if (value === void 0) value = 0;
        if (unit === void 0) unit = "%";
        return "translateX(" + value + (value ? unit : "") + ")";
    }
    function scale3d(value) {
        return "scale3d(" + value + ", " + value + ", 1)";
    }
    var Animations$1 = assign({}, Animations, {
        fade: {
            show: function () {
                return [{
                    opacity: 0
                }, {
                    opacity: 1
                }];
            },
            percent: function (current) {
                return 1 - css(current, "opacity");
            },
            translate: function (percent) {
                return [{
                    opacity: 1 - percent
                }, {
                    opacity: percent
                }];
            }
        },
        scale: {
            show: function () {
                return [{
                    opacity: 0,
                    transform: scale3d(1 - .2)
                }, {
                    opacity: 1,
                    transform: scale3d(1)
                }];
            },
            percent: function (current) {
                return 1 - css(current, "opacity");
            },
            translate: function (percent) {
                return [{
                    opacity: 1 - percent,
                    transform: scale3d(1 - .2 * percent)
                }, {
                    opacity: percent,
                    transform: scale3d(1 - .2 + .2 * percent)
                }];
            }
        }
    });
    function Transitioner(prev, next, dir, ref) {
        var animation = ref.animation;
        var easing = ref.easing;
        var percent = animation.percent;
        var translate = animation.translate;
        var show = animation.show;
        if (show === void 0) show = noop;
        var props = show(dir);
        var deferred = new Deferred();
        return {
            dir: dir,
            show: function (duration, percent, linear) {
                var this$1 = this;
                if (percent === void 0) percent = 0;
                var timing = linear ? "linear" : easing;
                duration -= Math.round(duration * clamp(percent, -1, 1));
                this.translate(percent);
                triggerUpdate(next, "itemin", {
                    percent: percent,
                    duration: duration,
                    timing: timing,
                    dir: dir
                });
                triggerUpdate(prev, "itemout", {
                    percent: 1 - percent,
                    duration: duration,
                    timing: timing,
                    dir: dir
                });
                Promise.all([Transition.start(next, props[1], duration, timing), Transition.start(prev, props[0], duration, timing)]).then(function () {
                    this$1.reset();
                    deferred.resolve();
                }, noop);
                return deferred.promise;
            },
            stop: function () {
                return Transition.stop([next, prev]);
            },
            cancel: function () {
                Transition.cancel([next, prev]);
            },
            reset: function () {
                for (var prop in props[0]) {
                    css([next, prev], prop, "");
                }
            },
            forward: function (duration, percent) {
                if (percent === void 0) percent = this.percent();
                Transition.cancel([next, prev]);
                return this.show(duration, percent, true);
            },
            translate: function (percent) {
                this.reset();
                var props = translate(percent, dir);
                css(next, props[1]);
                css(prev, props[0]);
                triggerUpdate(next, "itemtranslatein", {
                    percent: percent,
                    dir: dir
                });
                triggerUpdate(prev, "itemtranslateout", {
                    percent: 1 - percent,
                    dir: dir
                });
            },
            percent: function () {
                return percent(prev || next, next, dir);
            },
            getDistance: function () {
                return prev && prev.offsetWidth;
            }
        };
    }
    function triggerUpdate(el, type, data$$1) {
        trigger(el, createEvent(type, false, false, data$$1));
    }
    var SliderAutoplay = {
        props: {
            autoplay: Boolean,
            autoplayInterval: Number,
            pauseOnHover: Boolean
        },
        data: {
            autoplay: false,
            autoplayInterval: 7e3,
            pauseOnHover: true
        },
        connected: function () {
            this.startAutoplay();
            this.userInteracted = false;
        },
        disconnected: function () {
            this.stopAutoplay();
        },
        events: [{
            name: "visibilitychange",
            el: document,
            handler: function () {
                if (document.hidden) {
                    this.stopAutoplay();
                } else {
                    !this.userInteracted && this.startAutoplay();
                }
            }
        }, {
            name: pointerDown,
            handler: function () {
                this.userInteracted = true;
                this.stopAutoplay();
            }
        }, {
            name: "mouseenter",
            filter: function () {
                return this.autoplay;
            },
            handler: function () {
                this.isHovering = true;
            }
        }, {
            name: "mouseleave",
            filter: function () {
                return this.autoplay;
            },
            handler: function () {
                this.isHovering = false;
            }
        }],
        methods: {
            startAutoplay: function () {
                var this$1 = this;
                this.stopAutoplay();
                if (this.autoplay) {
                    this.interval = setInterval(function () {
                        return !(this$1.isHovering && this$1.pauseOnHover) && !this$1.stack.length && this$1.show("next");
                    }, this.autoplayInterval);
                }
            },
            stopAutoplay: function () {
                if (this.interval) {
                    clearInterval(this.interval);
                }
            }
        }
    };
    var SliderDrag = {
        props: {
            draggable: Boolean
        },
        data: {
            draggable: true,
            threshold: 10
        },
        created: function () {
            var this$1 = this;
            ["start", "move", "end"].forEach(function (key) {
                var fn = this$1[key];
                this$1[key] = function (e) {
                    var pos = getPos$1(e).x * (isRtl ? -1 : 1);
                    this$1.prevPos = pos !== this$1.pos ? this$1.pos : this$1.prevPos;
                    this$1.pos = pos;
                    fn(e);
                };
            });
        },
        events: [{
            name: pointerDown,
            delegate: function () {
                return this.selSlides;
            },
            handler: function (e) {
                if (!this.draggable || !isTouch(e) && hasTextNodesOnly(e.target) || e.button > 0 || this.length < 2) {
                    return;
                }
                this.start(e);
            }
        }, {
            name: "touchmove",
            passive: false,
            handler: "move",
            delegate: function () {
                return this.selSlides;
            }
        }, {
            name: "dragstart",
            handler: function (e) {
                e.preventDefault();
            }
        }],
        methods: {
            start: function () {
                var this$1 = this;
                this.drag = this.pos;
                if (this._transitioner) {
                    this.percent = this._transitioner.percent();
                    this.drag += this._transitioner.getDistance() * this.percent * this.dir;
                    this._transitioner.cancel();
                    this._transitioner.translate(this.percent);
                    this.dragging = true;
                    this.stack = [];
                } else {
                    this.prevIndex = this.index;
                }
                var off$$1 = pointerMove !== "touchmove" ? on(document, pointerMove, this.move, {
                    passive: false
                }) : noop;
                this.unbindMove = function () {
                    off$$1();
                    this$1.unbindMove = null;
                };
                on(window, "scroll", this.unbindMove);
                on(document, pointerUp, this.end, true);
            },
            move: function (e) {
                var this$1 = this;
                if (!this.unbindMove) {
                    return;
                }
                var distance = this.pos - this.drag;
                if (distance === 0 || this.prevPos === this.pos || !this.dragging && Math.abs(distance) < this.threshold) {
                    return;
                }
                e.cancelable && e.preventDefault();
                this.dragging = true;
                this.dir = distance < 0 ? 1 : -1;
                var ref = this;
                var slides = ref.slides;
                var ref$1 = this;
                var prevIndex = ref$1.prevIndex;
                var dis = Math.abs(distance);
                var nextIndex = this.getIndex(prevIndex + this.dir, prevIndex);
                var width$$1 = this._getDistance(prevIndex, nextIndex) || slides[prevIndex].offsetWidth;
                while (nextIndex !== prevIndex && dis > width$$1) {
                    this.drag -= width$$1 * this.dir;
                    prevIndex = nextIndex;
                    dis -= width$$1;
                    nextIndex = this.getIndex(prevIndex + this.dir, prevIndex);
                    width$$1 = this._getDistance(prevIndex, nextIndex) || slides[prevIndex].offsetWidth;
                }
                this.percent = dis / width$$1;
                var prev = slides[prevIndex];
                var next = slides[nextIndex];
                var changed = this.index !== nextIndex;
                var edge = prevIndex === nextIndex;
                var itemShown;
                [this.index, this.prevIndex].filter(function (i) {
                    return !includes([nextIndex, prevIndex], i);
                }).forEach(function (i) {
                    trigger(slides[i], "itemhidden", [this$1]);
                    if (edge) {
                        itemShown = true;
                        this$1.prevIndex = prevIndex;
                    }
                });
                if (this.index === prevIndex && this.prevIndex !== prevIndex || itemShown) {
                    trigger(slides[this.index], "itemshown", [this]);
                }
                if (changed) {
                    this.prevIndex = prevIndex;
                    this.index = nextIndex;
                    !edge && trigger(prev, "beforeitemhide", [this]);
                    trigger(next, "beforeitemshow", [this]);
                }
                this._transitioner = this._translate(Math.abs(this.percent), prev, !edge && next);
                if (changed) {
                    !edge && trigger(prev, "itemhide", [this]);
                    trigger(next, "itemshow", [this]);
                }
            },
            end: function () {
                off(window, "scroll", this.unbindMove);
                this.unbindMove && this.unbindMove();
                off(document, pointerUp, this.end, true);
                if (this.dragging) {
                    this.dragging = null;
                    if (this.index === this.prevIndex) {
                        this.percent = 1 - this.percent;
                        this.dir *= -1;
                        this._show(false, this.index, true);
                        this._transitioner = null;
                    } else {
                        var dirChange = (isRtl ? this.dir * (isRtl ? 1 : -1) : this.dir) < 0 === this.prevPos > this.pos;
                        this.index = dirChange ? this.index : this.prevIndex;
                        if (dirChange) {
                            this.percent = 1 - this.percent;
                        }
                        this.show(this.dir > 0 && !dirChange || this.dir < 0 && dirChange ? "next" : "previous", true);
                    }
                    preventClick();
                }
                this.drag = this.percent = null;
            }
        }
    };
    function hasTextNodesOnly(el) {
        return !el.children.length && el.childNodes.length;
    }
    var SliderNav = {
        data: {
            selNav: false
        },
        computed: {
            nav: function (ref, $el) {
                var selNav = ref.selNav;
                return $(selNav, $el);
            },
            selNavItem: function (ref) {
                var attrItem = ref.attrItem;
                return "[" + attrItem + "],[data-" + attrItem + "]";
            },
            navItems: function (_, $el) {
                return $$(this.selNavItem, $el);
            }
        },
        update: {
            write: function () {
                var this$1 = this;
                if (this.nav && this.length !== this.nav.children.length) {
                    html(this.nav, this.slides.map(function (_, i) {
                        return "<li " + this$1.attrItem + '="' + i + '"><a href="#"></a></li>';
                    }).join(""));
                }
                toggleClass($$(this.selNavItem, this.$el).concat(this.nav), "uk-hidden", !this.maxIndex);
                this.updateNav();
            },
            events: ["resize"]
        },
        events: [{
            name: "click",
            delegate: function () {
                return this.selNavItem;
            },
            handler: function (e) {
                e.preventDefault();
                this.show(data(e.current, this.attrItem));
            }
        }, {
            name: "itemshow",
            handler: "updateNav"
        }],
        methods: {
            updateNav: function () {
                var this$1 = this;
                var i = this.getValidIndex();
                this.navItems.forEach(function (el) {
                    var cmd = data(el, this$1.attrItem);
                    toggleClass(el, this$1.clsActive, toNumber(cmd) === i);
                    toggleClass(el, "uk-invisible", this$1.finite && (cmd === "previous" && i === 0 || cmd === "next" && i >= this$1.maxIndex));
                });
            }
        }
    };
    var Slider = {
        mixins: [SliderAutoplay, SliderDrag, SliderNav],
        props: {
            clsActivated: Boolean,
            easing: String,
            index: Number,
            finite: Boolean,
            velocity: Number
        },
        data: function () {
            return {
                easing: "ease",
                finite: false,
                velocity: 1,
                index: 0,
                stack: [],
                percent: 0,
                clsActive: "uk-active",
                clsActivated: false,
                Transitioner: false,
                transitionOptions: {}
            };
        },
        computed: {
            duration: function (ref, $el) {
                var velocity = ref.velocity;
                return speedUp($el.offsetWidth / velocity);
            },
            length: function () {
                return this.slides.length;
            },
            list: function (ref, $el) {
                var selList = ref.selList;
                return $(selList, $el);
            },
            maxIndex: function () {
                return this.length - 1;
            },
            selSlides: function (ref) {
                var selList = ref.selList;
                return selList + " > *";
            },
            slides: function () {
                return toNodes(this.list.children);
            }
        },
        events: {
            itemshown: function () {
                this.$update(this.list);
            }
        },
        methods: {
            show: function (index$$1, force) {
                var this$1 = this;
                if (force === void 0) force = false;
                if (this.dragging || !this.length) {
                    return;
                }
                var ref = this;
                var stack = ref.stack;
                var queueIndex = force ? 0 : stack.length;
                var reset = function () {
                    stack.splice(queueIndex, 1);
                    if (stack.length) {
                        this$1.show(stack.shift(), true);
                    }
                };
                stack[force ? "unshift" : "push"](index$$1);
                if (!force && stack.length > 1) {
                    if (stack.length === 2) {
                        this._transitioner.forward(Math.min(this.duration, 200));
                    }
                    return;
                }
                var prevIndex = this.index;
                var prev = hasClass(this.slides, this.clsActive) && this.slides[prevIndex];
                var nextIndex = this.getIndex(index$$1, this.index);
                var next = this.slides[nextIndex];
                if (prev === next) {
                    reset();
                    return;
                }
                this.dir = getDirection(index$$1, prevIndex);
                this.prevIndex = prevIndex;
                this.index = nextIndex;
                prev && trigger(prev, "beforeitemhide", [this]);
                if (!trigger(next, "beforeitemshow", [this, prev])) {
                    this.index = this.prevIndex;
                    reset();
                    return;
                }
                var promise = this._show(prev, next, force).then(function () {
                    prev && trigger(prev, "itemhidden", [this$1]);
                    trigger(next, "itemshown", [this$1]);
                    return new Promise(function (resolve) {
                        fastdom.write(function () {
                            stack.shift();
                            if (stack.length) {
                                this$1.show(stack.shift(), true);
                            } else {
                                this$1._transitioner = null;
                            }
                            resolve();
                        });
                    });
                });
                prev && trigger(prev, "itemhide", [this]);
                trigger(next, "itemshow", [this]);
                return promise;
            },
            getIndex: function (index$$1, prev) {
                if (index$$1 === void 0) index$$1 = this.index;
                if (prev === void 0) prev = this.index;
                return clamp(getIndex(index$$1, this.slides, prev, this.finite), 0, this.maxIndex);
            },
            getValidIndex: function (index$$1, prevIndex) {
                if (index$$1 === void 0) index$$1 = this.index;
                if (prevIndex === void 0) prevIndex = this.prevIndex;
                return this.getIndex(index$$1, prevIndex);
            },
            _show: function (prev, next, force) {
                this._transitioner = this._getTransitioner(prev, next, this.dir, assign({
                    easing: force ? next.offsetWidth < 600 ? "cubic-bezier(0.25, 0.46, 0.45, 0.94)" : "cubic-bezier(0.165, 0.84, 0.44, 1)" : this.easing
                }, this.transitionOptions));
                if (!force && !prev) {
                    this._transitioner.translate(1);
                    return Promise.resolve();
                }
                var ref = this.stack;
                var length = ref.length;
                return this._transitioner[length > 1 ? "forward" : "show"](length > 1 ? Math.min(this.duration, 75 + 75 / (length - 1)) : this.duration, this.percent);
            },
            _getDistance: function (prev, next) {
                return new this._getTransitioner(prev, prev !== next && next).getDistance();
            },
            _translate: function (percent, prev, next) {
                if (prev === void 0) prev = this.prevIndex;
                if (next === void 0) next = this.index;
                var transitioner = this._getTransitioner(prev !== next ? prev : false, next);
                transitioner.translate(percent);
                return transitioner;
            },
            _getTransitioner: function (prev, next, dir, options) {
                if (prev === void 0) prev = this.prevIndex;
                if (next === void 0) next = this.index;
                if (dir === void 0) dir = this.dir || 1;
                if (options === void 0) options = this.transitionOptions;
                return new this.Transitioner(isNumber(prev) ? this.slides[prev] : prev, isNumber(next) ? this.slides[next] : next, dir * (isRtl ? -1 : 1), options);
            }
        }
    };
    function getDirection(index$$1, prevIndex) {
        return index$$1 === "next" ? 1 : index$$1 === "previous" ? -1 : index$$1 < prevIndex ? -1 : 1;
    }
    function speedUp(x) {
        return .5 * x + 300;
    }
    var Slideshow = {
        mixins: [Slider],
        props: {
            animation: String
        },
        data: {
            animation: "slide",
            clsActivated: "uk-transition-active",
            Animations: Animations,
            Transitioner: Transitioner
        },
        computed: {
            animation: function (ref) {
                var animation = ref.animation;
                var Animations$$1 = ref.Animations;
                return assign(animation in Animations$$1 ? Animations$$1[animation] : Animations$$1.slide, {
                    name: animation
                });
            },
            transitionOptions: function () {
                return {
                    animation: this.animation
                };
            }
        },
        events: {
            "itemshow itemhide itemshown itemhidden": function (ref) {
                var target = ref.target;
                this.$update(target);
            },
            itemshow: function () {
                isNumber(this.prevIndex) && fastdom.flush();
            },
            beforeitemshow: function (ref) {
                var target = ref.target;
                addClass(target, this.clsActive);
            },
            itemshown: function (ref) {
                var target = ref.target;
                addClass(target, this.clsActivated);
            },
            itemhidden: function (ref) {
                var target = ref.target;
                removeClass(target, this.clsActive, this.clsActivated);
            }
        }
    };
    var LightboxPanel = {
        mixins: [Container, Modal, Togglable, Slideshow],
        functional: true,
        props: {
            delayControls: Number,
            preload: Number,
            videoAutoplay: Boolean,
            template: String
        },
        data: function () {
            return {
                preload: 1,
                videoAutoplay: false,
                delayControls: 3e3,
                items: [],
                cls: "uk-open",
                clsPage: "uk-lightbox-page",
                selList: ".uk-lightbox-items",
                attrItem: "uk-lightbox-item",
                selClose: ".uk-close-large",
                pauseOnHover: false,
                velocity: 2,
                Animations: Animations$1,
                template: '<div class="uk-lightbox uk-overflow-hidden"> <ul class="uk-lightbox-items"></ul> <div class="uk-lightbox-toolbar uk-position-top uk-text-right uk-transition-slide-top uk-transition-opaque"> <button class="uk-lightbox-toolbar-icon uk-close-large" type="button" uk-close></button> </div> <a class="uk-lightbox-button uk-position-center-left uk-position-medium uk-transition-fade" href="#" uk-slidenav-previous uk-lightbox-item="previous"></a> <a class="uk-lightbox-button uk-position-center-right uk-position-medium uk-transition-fade" href="#" uk-slidenav-next uk-lightbox-item="next"></a> <div class="uk-lightbox-toolbar uk-lightbox-caption uk-position-bottom uk-text-center uk-transition-slide-bottom uk-transition-opaque"></div> </div>'
            };
        },
        created: function () {
            var this$1 = this;
            this.$mount(append(this.container, this.template));
            this.caption = $(".uk-lightbox-caption", this.$el);
            this.items.forEach(function () {
                return append(this$1.list, "<li></li>");
            });
        },
        events: [{
            name: pointerMove + " " + pointerDown + " keydown",
            handler: "showControls"
        }, {
            name: pointerUp,
            self: true,
            delegate: function () {
                return this.selSlides;
            },
            handler: function (e) {
                e.preventDefault();
                this.hide();
            }
        }, {
            name: "shown",
            self: true,
            handler: function () {
                this.startAutoplay();
                this.showControls();
            }
        }, {
            name: "hide",
            self: true,
            handler: function () {
                this.stopAutoplay();
                this.hideControls();
                removeClass(this.slides, this.clsActive);
                Transition.stop(this.slides);
            }
        }, {
            name: "hidden",
            self: true,
            handler: function () {
                this.$destroy(true);
            }
        }, {
            name: "keyup",
            el: document,
            handler: function (e) {
                if (!this.isToggled(this.$el)) {
                    return;
                }
                switch (e.keyCode) {
                    case 37:
                        this.show("previous");
                        break;

                    case 39:
                        this.show("next");
                        break;
                }
            }
        }, {
            name: "beforeitemshow",
            handler: function (e) {
                if (this.isToggled()) {
                    return;
                }
                this.draggable = false;
                e.preventDefault();
                this.toggleNow(this.$el, true);
                this.animation = Animations$1["scale"];
                removeClass(e.target, this.clsActive);
                this.stack.splice(1, 0, this.index);
            }
        }, {
            name: "itemshow",
            handler: function (ref) {
                var target = ref.target;
                var i = index(target);
                var ref$1 = this.getItem(i);
                var caption = ref$1.caption;
                css(this.caption, "display", caption ? "" : "none");
                html(this.caption, caption);
                for (var j = 0; j <= this.preload; j++) {
                    this.loadItem(this.getIndex(i + j));
                    this.loadItem(this.getIndex(i - j));
                }
            }
        }, {
            name: "itemshown",
            handler: function () {
                this.draggable = this.$props.draggable;
            }
        }, {
            name: "itemload",
            handler: function (_, item) {
                var this$1 = this;
                var source = item.source;
                var type = item.type;
                var alt = item.alt;
                this.setItem(item, "<span uk-spinner></span>");
                if (!source) {
                    return;
                }
                var matches$$1;
                if (type === "image" || source.match(/\.(jp(e)?g|png|gif|svg)($|\?)/i)) {
                    getImage(source).then(function (img) {
                        return this$1.setItem(item, '<img width="' + img.width + '" height="' + img.height + '" src="' + source + '" alt="' + (alt ? alt : "") + '">');
                    }, function () {
                        return this$1.setError(item);
                    });
                } else if (type === "video" || source.match(/\.(mp4|webm|ogv)($|\?)/i)) {
                    var video = $("<video controls playsinline" + (item.poster ? ' poster="' + item.poster + '"' : "") + ' uk-video="' + this.videoAutoplay + '"></video>');
                    attr(video, "src", source);
                    once(video, "error loadedmetadata", function (type) {
                        if (type === "error") {
                            this$1.setError(item);
                        } else {
                            attr(video, {
                                width: video.videoWidth,
                                height: video.videoHeight
                            });
                            this$1.setItem(item, video);
                        }
                    });
                } else if (type === "iframe" || source.match(/\.(html|php)($|\?)/i)) {
                    this.setItem(item, '<iframe class="uk-lightbox-iframe" src="' + source + '" frameborder="0" allowfullscreen></iframe>');
                } else if (matches$$1 = source.match(/\/\/.*?youtube(-nocookie)?\.[a-z]+\/watch\?v=([^&\s]+)/) || source.match(/()youtu\.be\/(.*)/)) {
                    var id = matches$$1[2];
                    var setIframe = function (width$$1, height$$1) {
                        if (width$$1 === void 0) width$$1 = 640;
                        if (height$$1 === void 0) height$$1 = 450;
                        return this$1.setItem(item, getIframe("https://www.youtube" + (matches$$1[1] || "") + ".com/embed/" + id, width$$1, height$$1, this$1.videoAutoplay));
                    };
                    getImage("https://img.youtube.com/vi/" + id + "/maxresdefault.jpg").then(function (ref) {
                        var width$$1 = ref.width;
                        var height$$1 = ref.height;
                        if (width$$1 === 120 && height$$1 === 90) {
                            getImage("https://img.youtube.com/vi/" + id + "/0.jpg").then(function (ref) {
                                var width$$1 = ref.width;
                                var height$$1 = ref.height;
                                return setIframe(width$$1, height$$1);
                            }, setIframe);
                        } else {
                            setIframe(width$$1, height$$1);
                        }
                    }, setIframe);
                } else if (matches$$1 = source.match(/(\/\/.*?)vimeo\.[a-z]+\/([0-9]+).*?/)) {
                    ajax("https://vimeo.com/api/oembed.json?maxwidth=1920&url=" + encodeURI(source), {
                        responseType: "json",
                        withCredentials: false
                    }).then(function (ref) {
                        var ref_response = ref.response;
                        var height$$1 = ref_response.height;
                        var width$$1 = ref_response.width;
                        return this$1.setItem(item, getIframe("https://player.vimeo.com/video/" + matches$$1[2], width$$1, height$$1, this$1.videoAutoplay));
                    }, function () {
                        return this$1.setError(item);
                    });
                }
            }
        }],
        methods: {
            loadItem: function (index$$1) {
                if (index$$1 === void 0) index$$1 = this.index;
                var item = this.getItem(index$$1);
                if (item.content) {
                    return;
                }
                trigger(this.$el, "itemload", [item]);
            },
            getItem: function (index$$1) {
                if (index$$1 === void 0) index$$1 = this.index;
                return this.items[index$$1] || {};
            },
            setItem: function (item, content) {
                assign(item, {
                    content: content
                });
                var el = html(this.slides[this.items.indexOf(item)], content);
                trigger(this.$el, "itemloaded", [this, el]);
                this.$update(el);
            },
            setError: function (item) {
                this.setItem(item, '<span uk-icon="icon: bolt; ratio: 2"></span>');
            },
            showControls: function () {
                clearTimeout(this.controlsTimer);
                this.controlsTimer = setTimeout(this.hideControls, this.delayControls);
                addClass(this.$el, "uk-active", "uk-transition-active");
            },
            hideControls: function () {
                removeClass(this.$el, "uk-active", "uk-transition-active");
            }
        }
    };
    function getIframe(src, width$$1, height$$1, autoplay) {
        return '<iframe src="' + src + '" width="' + width$$1 + '" height="' + height$$1 + '" style="max-width: 100%; box-sizing: border-box;" frameborder="0" allowfullscreen uk-video="autoplay: ' + autoplay + '" uk-responsive></iframe>';
    }
    var Lightbox = {
        install: install$2,
        props: {
            toggle: String
        },
        data: {
            toggle: "a"
        },
        computed: {
            toggles: {
                get: function (ref, $el) {
                    var toggle = ref.toggle;
                    return $$(toggle, $el);
                },
                watch: function () {
                    this.hide();
                }
            }
        },
        disconnected: function () {
            this.hide();
        },
        events: [{
            name: "click",
            delegate: function () {
                return this.toggle + ":not(.uk-disabled)";
            },
            handler: function (e) {
                e.preventDefault();
                this.show(index(this.toggles, e.current));
            }
        }],
        methods: {
            show: function (index$$1) {
                var this$1 = this;
                this.panel = this.panel || this.$create("lightboxPanel", assign({}, this.$props, {
                    items: this.toggles.reduce(function (items, el) {
                        items.push(["href", "caption", "type", "poster", "alt"].reduce(function (obj, attr$$1) {
                            obj[attr$$1 === "href" ? "source" : attr$$1] = data(el, attr$$1);
                            return obj;
                        }, {}));
                        return items;
                    }, [])
                }));
                on(this.panel.$el, "hidden", function () {
                    return this$1.panel = false;
                });
                return this.panel.show(index$$1);
            },
            hide: function () {
                return this.panel && this.panel.hide();
            }
        }
    };
    function install$2(UIkit, Lightbox) {
        if (!UIkit.lightboxPanel) {
            UIkit.component("lightboxPanel", LightboxPanel);
        }
        assign(Lightbox.props, UIkit.component("lightboxPanel").options.props);
    }
    var obj;
    var containers = {};
    var Notification = {
        functional: true,
        args: ["message", "status"],
        data: {
            message: "",
            status: "",
            timeout: 5e3,
            group: null,
            pos: "top-center",
            clsClose: "uk-notification-close",
            clsMsg: "uk-notification-message"
        },
        install: install$3,
        computed: {
            marginProp: function (ref) {
                var pos = ref.pos;
                return "margin" + (startsWith(pos, "top") ? "Top" : "Bottom");
            },
            startProps: function () {
                var obj;
                return obj = {
                    opacity: 0
                }, obj[this.marginProp] = -this.$el.offsetHeight, obj;
            }
        },
        created: function () {
            if (!containers[this.pos]) {
                containers[this.pos] = append(this.$container, '<div class="uk-notification uk-notification-' + this.pos + '"></div>');
            }
            var container = css(containers[this.pos], "display", "block");
            this.$mount(append(container, '<div class="' + this.clsMsg + (this.status ? " " + this.clsMsg + "-" + this.status : "") + '"> <a href="#" class="' + this.clsClose + '" data-uk-close></a> <div>' + this.message + "</div> </div>"));
        },
        connected: function () {
            var this$1 = this;
            var obj;
            var margin = toFloat(css(this.$el, this.marginProp));
            Transition.start(css(this.$el, this.startProps), (obj = {
                opacity: 1
            }, obj[this.marginProp] = margin, obj)).then(function () {
                if (this$1.timeout) {
                    this$1.timer = setTimeout(this$1.close, this$1.timeout);
                }
            });
        },
        events: (obj = {
            click: function (e) {
                if (closest(e.target, 'a[href="#"],a[href=""]')) {
                    e.preventDefault();
                }
                this.close();
            }
        }, obj[pointerEnter] = function () {
            if (this.timer) {
                clearTimeout(this.timer);
            }
        }, obj[pointerLeave] = function () {
            if (this.timeout) {
                this.timer = setTimeout(this.close, this.timeout);
            }
        }, obj),
        methods: {
            close: function (immediate) {
                var this$1 = this;
                var removeFn = function () {
                    trigger(this$1.$el, "close", [this$1]);
                    remove(this$1.$el);
                    if (!containers[this$1.pos].children.length) {
                        css(containers[this$1.pos], "display", "none");
                    }
                };
                if (this.timer) {
                    clearTimeout(this.timer);
                }
                if (immediate) {
                    removeFn();
                } else {
                    Transition.start(this.$el, this.startProps).then(removeFn);
                }
            }
        }
    };
    function install$3(UIkit) {
        UIkit.notification.closeAll = function (group, immediate) {
            apply(document.body, function (el) {
                var notification = UIkit.getComponent(el, "notification");
                if (notification && (!group || group === notification.group)) {
                    notification.close(immediate);
                }
            });
        };
    }
    var props = ["x", "y", "bgx", "bgy", "rotate", "scale", "color", "backgroundColor", "borderColor", "opacity", "blur", "hue", "grayscale", "invert", "saturate", "sepia", "fopacity"];
    var Parallax = {
        mixins: [Media],
        props: props.reduce(function (props, prop) {
            props[prop] = "list";
            return props;
        }, {}),
        data: props.reduce(function (data$$1, prop) {
            data$$1[prop] = undefined;
            return data$$1;
        }, {}),
        computed: {
            props: function (properties, $el) {
                var this$1 = this;
                return props.reduce(function (props, prop) {
                    if (isUndefined(properties[prop])) {
                        return props;
                    }
                    var isColor = prop.match(/color/i);
                    var isCssProp = isColor || prop === "opacity";
                    var pos, bgPos, diff;
                    var steps = properties[prop].slice(0);
                    if (isCssProp) {
                        css($el, prop, "");
                    }
                    if (steps.length < 2) {
                        steps.unshift((prop === "scale" ? 1 : isCssProp ? css($el, prop) : 0) || 0);
                    }
                    var unit = includes(steps.join(""), "%") ? "%" : "px";
                    if (isColor) {
                        var ref = $el.style;
                        var color = ref.color;
                        steps = steps.map(function (step) {
                            return parseColor($el, step);
                        });
                        $el.style.color = color;
                    } else {
                        steps = steps.map(toFloat);
                    }
                    if (prop.match(/^bg/)) {
                        css($el, "background-position-" + prop[2], "");
                        bgPos = css($el, "backgroundPosition").split(" ")[prop[2] === "x" ? 0 : 1];
                        if (this$1.covers) {
                            var min = Math.min.apply(Math, steps);
                            var max = Math.max.apply(Math, steps);
                            var down = steps.indexOf(min) < steps.indexOf(max);
                            diff = max - min;
                            steps = steps.map(function (step) {
                                return step - (down ? min : max);
                            });
                            pos = (down ? -diff : 0) + "px";
                        } else {
                            pos = bgPos;
                        }
                    }
                    props[prop] = {
                        steps: steps,
                        unit: unit,
                        pos: pos,
                        bgPos: bgPos,
                        diff: diff
                    };
                    return props;
                }, {});
            },
            bgProps: function () {
                var this$1 = this;
                return ["bgx", "bgy"].filter(function (bg) {
                    return bg in this$1.props;
                });
            },
            covers: function (_, $el) {
                return covers($el);
            }
        },
        disconnected: function () {
            delete this._image;
        },
        update: {
            read: function (data$$1) {
                var this$1 = this;
                data$$1.active = this.matchMedia;
                if (!data$$1.active) {
                    return;
                }
                if (!data$$1.image && this.covers && this.bgProps.length) {
                    var src = css(this.$el, "backgroundImage").replace(/^none|url\(["']?(.+?)["']?\)$/, "$1");
                    if (src) {
                        var img = new Image();
                        img.src = src;
                        data$$1.image = img;
                        if (!img.naturalWidth) {
                            img.onload = function () {
                                return this$1.$emit();
                            };
                        }
                    }
                }
                var image = data$$1.image;
                if (!image || !image.naturalWidth) {
                    return;
                }
                var dimEl = {
                    width: this.$el.offsetWidth,
                    height: this.$el.offsetHeight
                };
                var dimImage = {
                    width: image.naturalWidth,
                    height: image.naturalHeight
                };
                var dim = Dimensions.cover(dimImage, dimEl);
                this.bgProps.forEach(function (prop) {
                    var ref = this$1.props[prop];
                    var diff = ref.diff;
                    var bgPos = ref.bgPos;
                    var steps = ref.steps;
                    var attr$$1 = prop === "bgy" ? "height" : "width";
                    var span = dim[attr$$1] - dimEl[attr$$1];
                    if (!bgPos.match(/%$|0px/)) {
                        return;
                    }
                    if (span < diff) {
                        dimEl[attr$$1] = dim[attr$$1] + diff - span;
                    } else if (span > diff) {
                        var bgPosFloat = parseFloat(bgPos);
                        if (bgPosFloat) {
                            this$1.props[prop].steps = steps.map(function (step) {
                                return step - (span - diff) / (100 / bgPosFloat);
                            });
                        }
                    }
                    dim = Dimensions.cover(dimImage, dimEl);
                });
                data$$1.dim = dim;
            },
            write: function (ref) {
                var dim = ref.dim;
                var active = ref.active;
                if (!active) {
                    css(this.$el, {
                        backgroundSize: "",
                        backgroundRepeat: ""
                    });
                    return;
                }
                dim && css(this.$el, {
                    backgroundSize: dim.width + "px " + dim.height + "px",
                    backgroundRepeat: "no-repeat"
                });
            },
            events: ["resize"]
        },
        methods: {
            reset: function () {
                var this$1 = this;
                each(this.getCss(0), function (_, prop) {
                    return css(this$1.$el, prop, "");
                });
            },
            getCss: function (percent) {
                var ref = this;
                var props = ref.props;
                var translated = false;
                return Object.keys(props).reduce(function (css$$1, prop) {
                    var ref = props[prop];
                    var steps = ref.steps;
                    var unit = ref.unit;
                    var pos = ref.pos;
                    var value = getValue(steps, percent);
                    switch (prop) {
                        case "x":
                        case "y":
                            {
                                if (translated) {
                                    break;
                                }
                                var ref$1 = ["x", "y"].map(function (dir) {
                                    return prop === dir ? toFloat(value).toFixed(0) + unit : props[dir] ? getValue(props[dir].steps, percent, 1) + props[dir].unit : 0;
                                });
                                var x = ref$1[0];
                                var y = ref$1[1];
                                translated = css$$1.transform += " translate3d(" + x + ", " + y + ", 0)";
                                break;
                            }

                        case "rotate":
                            css$$1.transform += " rotate(" + value + "deg)";
                            break;

                        case "scale":
                            css$$1.transform += " scale(" + value + ")";
                            break;

                        case "bgy":
                        case "bgx":
                            css$$1["background-position-" + prop[2]] = "calc(" + pos + " + " + (value + unit) + ")";
                            break;

                        case "color":
                        case "backgroundColor":
                        case "borderColor":
                            {
                                var ref$2 = getStep(steps, percent);
                                var start = ref$2[0];
                                var end = ref$2[1];
                                var p = ref$2[2];
                                css$$1[prop] = "rgba(" + start.map(function (value, i) {
                                    value = value + p * (end[i] - value);
                                    return i === 3 ? toFloat(value) : parseInt(value, 10);
                                }).join(",") + ")";
                                break;
                            }

                        case "blur":
                            css$$1.filter += " blur(" + value + "px)";
                            break;

                        case "hue":
                            css$$1.filter += " hue-rotate(" + value + "deg)";
                            break;

                        case "fopacity":
                            css$$1.filter += " opacity(" + value + "%)";
                            break;

                        case "grayscale":
                        case "invert":
                        case "saturate":
                        case "sepia":
                            css$$1.filter += " " + prop + "(" + value + "%)";
                            break;

                        default:
                            css$$1[prop] = value;
                    }
                    return css$$1;
                }, {
                    transform: "",
                    filter: ""
                });
            }
        }
    };
    function parseColor(el, color) {
        return css(css(el, "color", color), "color").split(/[(),]/g).slice(1, -1).concat(1).slice(0, 4).map(function (n) {
            return toFloat(n);
        });
    }
    function getStep(steps, percent) {
        var count = steps.length - 1;
        var index$$1 = Math.min(Math.floor(count * percent), count - 1);
        var step = steps.slice(index$$1, index$$1 + 2);
        step.push(percent === 1 ? 1 : percent % (1 / count) * count);
        return step;
    }
    function getValue(steps, percent, digits) {
        if (digits === void 0) digits = 2;
        var ref = getStep(steps, percent);
        var start = ref[0];
        var end = ref[1];
        var p = ref[2];
        return (isNumber(start) ? start + Math.abs(start - end) * p * (start < end ? 1 : -1) : +end).toFixed(digits);
    }
    function covers(el) {
        var ref = el.style;
        var backgroundSize = ref.backgroundSize;
        var covers = css(css(el, "backgroundSize", ""), "backgroundSize") === "cover";
        el.style.backgroundSize = backgroundSize;
        return covers;
    }
    var Parallax$1 = {
        mixins: [Parallax],
        props: {
            target: String,
            viewport: Number,
            easing: Number
        },
        data: {
            target: false,
            viewport: 1,
            easing: 1
        },
        computed: {
            target: function (ref, $el) {
                var target = ref.target;
                return getOffsetElement(target && query(target, $el) || $el);
            }
        },
        update: {
            read: function (ref, type) {
                var percent = ref.percent;
                var active = ref.active;
                if (type !== "scroll") {
                    percent = false;
                }
                if (!active) {
                    return;
                }
                var prev = percent;
                percent = ease$1(scrolledOver(this.target) / (this.viewport || 1), this.easing);
                return {
                    percent: percent,
                    style: prev !== percent ? this.getCss(percent) : false
                };
            },
            write: function (ref) {
                var style = ref.style;
                var active = ref.active;
                if (!active) {
                    this.reset();
                    return;
                }
                style && css(this.$el, style);
            },
            events: ["scroll", "resize"]
        }
    };
    function ease$1(percent, easing) {
        return clamp(percent * (1 - (easing - easing * percent)));
    }
    function getOffsetElement(el) {
        return el ? "offsetTop" in el ? el : getOffsetElement(el.parentNode) : document.body;
    }
    var SliderReactive = {
        update: {
            write: function () {
                if (this.stack.length || this.dragging) {
                    return;
                }
                var index$$1 = this.getValidIndex();
                delete this.index;
                removeClass(this.slides, this.clsActive, this.clsActivated);
                this.show(index$$1);
            },
            events: ["resize"]
        }
    };
    function Transitioner$1(prev, next, dir, ref) {
        var center = ref.center;
        var easing = ref.easing;
        var list = ref.list;
        var deferred = new Deferred();
        var from = prev ? getLeft(prev, list, center) : getLeft(next, list, center) + bounds(next).width * dir;
        var to = next ? getLeft(next, list, center) : from + bounds(prev).width * dir * (isRtl ? -1 : 1);
        return {
            dir: dir,
            show: function (duration, percent, linear) {
                if (percent === void 0) percent = 0;
                var timing = linear ? "linear" : easing;
                duration -= Math.round(duration * clamp(percent, -1, 1));
                this.translate(percent);
                prev && this.updateTranslates();
                percent = prev ? percent : clamp(percent, 0, 1);
                triggerUpdate$1(this.getItemIn(), "itemin", {
                    percent: percent,
                    duration: duration,
                    timing: timing,
                    dir: dir
                });
                prev && triggerUpdate$1(this.getItemIn(true), "itemout", {
                    percent: 1 - percent,
                    duration: duration,
                    timing: timing,
                    dir: dir
                });
                Transition.start(list, {
                    transform: translate(-to * (isRtl ? -1 : 1), "px")
                }, duration, timing).then(deferred.resolve, noop);
                return deferred.promise;
            },
            stop: function () {
                return Transition.stop(list);
            },
            cancel: function () {
                Transition.cancel(list);
            },
            reset: function () {
                css(list, "transform", "");
            },
            forward: function (duration, percent) {
                if (percent === void 0) percent = this.percent();
                Transition.cancel(list);
                return this.show(duration, percent, true);
            },
            translate: function (percent) {
                var distance = this.getDistance() * dir * (isRtl ? -1 : 1);
                css(list, "transform", translate(clamp(-to + (distance - distance * percent), -getWidth(list), bounds(list).width) * (isRtl ? -1 : 1), "px"));
                this.updateTranslates();
                if (prev) {
                    percent = clamp(percent, -1, 1);
                    triggerUpdate$1(this.getItemIn(), "itemtranslatein", {
                        percent: percent,
                        dir: dir
                    });
                    triggerUpdate$1(this.getItemIn(true), "itemtranslateout", {
                        percent: 1 - percent,
                        dir: dir
                    });
                }
            },
            percent: function () {
                return Math.abs((css(list, "transform").split(",")[4] * (isRtl ? -1 : 1) + from) / (to - from));
            },
            getDistance: function () {
                return Math.abs(to - from);
            },
            getItemIn: function (out) {
                if (out === void 0) out = false;
                var actives = this.getActives();
                var all = sortBy(slides(list), "offsetLeft");
                var i = index(all, actives[dir * (out ? -1 : 1) > 0 ? actives.length - 1 : 0]);
                return ~i && all[i + (prev && !out ? dir : 0)];
            },
            getActives: function () {
                var left = getLeft(prev || next, list, center);
                return sortBy(slides(list).filter(function (slide) {
                    var slideLeft = getElLeft(slide, list);
                    return slideLeft >= left && slideLeft + bounds(slide).width <= bounds(list).width + left;
                }), "offsetLeft");
            },
            updateTranslates: function () {
                var actives = this.getActives();
                slides(list).forEach(function (slide) {
                    var isActive = includes(actives, slide);
                    triggerUpdate$1(slide, "itemtranslate" + (isActive ? "in" : "out"), {
                        percent: isActive ? 1 : 0,
                        dir: slide.offsetLeft <= next.offsetLeft ? 1 : -1
                    });
                });
            }
        };
    }
    function getLeft(el, list, center) {
        var left = getElLeft(el, list);
        return center ? left - centerEl(el, list) : Math.min(left, getMax(list));
    }
    function getMax(list) {
        return Math.max(0, getWidth(list) - bounds(list).width);
    }
    function getWidth(list) {
        return slides(list).reduce(function (right, el) {
            return bounds(el).width + right;
        }, 0);
    }
    function getMaxWidth(list) {
        return slides(list).reduce(function (right, el) {
            return Math.max(right, bounds(el).width);
        }, 0);
    }
    function centerEl(el, list) {
        return bounds(list).width / 2 - bounds(el).width / 2;
    }
    function getElLeft(el, list) {
        return (position(el).left + (isRtl ? bounds(el).width - bounds(list).width : 0)) * (isRtl ? -1 : 1);
    }
    function bounds(el) {
        return el.getBoundingClientRect();
    }
    function triggerUpdate$1(el, type, data$$1) {
        trigger(el, createEvent(type, false, false, data$$1));
    }
    function slides(list) {
        return toNodes(list.children);
    }
    var Slider$1 = {
        mixins: [Class, Slider, SliderReactive],
        props: {
            center: Boolean,
            sets: Boolean
        },
        data: {
            center: false,
            sets: false,
            attrItem: "uk-slider-item",
            selList: ".uk-slider-items",
            selNav: ".uk-slider-nav",
            clsContainer: "uk-slider-container",
            Transitioner: Transitioner$1
        },
        computed: {
            avgWidth: function () {
                return getWidth(this.list) / this.length;
            },
            finite: function (ref) {
                var finite = ref.finite;
                return finite || getWidth(this.list) < bounds(this.list).width + getMaxWidth(this.list) + this.center;
            },
            maxIndex: function () {
                if (!this.finite || this.center && !this.sets) {
                    return this.length - 1;
                }
                if (this.center) {
                    return this.sets[this.sets.length - 1];
                }
                css(this.slides, "order", "");
                var max = getMax(this.list);
                var i = this.length;
                while (i--) {
                    if (getElLeft(this.list.children[i], this.list) < max) {
                        return Math.min(i + 1, this.length - 1);
                    }
                }
                return 0;
            },
            sets: function (ref) {
                var this$1 = this;
                var sets = ref.sets;
                var width$$1 = bounds(this.list).width / (this.center ? 2 : 1);
                var left = 0;
                var leftCenter = width$$1;
                var slideLeft = 0;
                sets = sets && this.slides.reduce(function (sets, slide, i) {
                    var ref = bounds(slide);
                    var slideWidth = ref.width;
                    var slideRight = slideLeft + slideWidth;
                    if (slideRight > left) {
                        if (!this$1.center && i > this$1.maxIndex) {
                            i = this$1.maxIndex;
                        }
                        if (!includes(sets, i)) {
                            var cmp = this$1.slides[i + 1];
                            if (this$1.center && cmp && slideWidth < leftCenter - bounds(cmp).width / 2) {
                                leftCenter -= slideWidth;
                            } else {
                                leftCenter = width$$1;
                                sets.push(i);
                                left = slideLeft + width$$1 + (this$1.center ? slideWidth / 2 : 0);
                            }
                        }
                    }
                    slideLeft += slideWidth;
                    return sets;
                }, []);
                return sets && sets.length && sets;
            },
            transitionOptions: function () {
                return {
                    center: this.center,
                    list: this.list
                };
            }
        },
        connected: function () {
            toggleClass(this.$el, this.clsContainer, !$("." + this.clsContainer, this.$el));
        },
        update: {
            write: function () {
                var this$1 = this;
                $$("[" + this.attrItem + "],[data-" + this.attrItem + "]", this.$el).forEach(function (el) {
                    var index$$1 = data(el, this$1.attrItem);
                    this$1.maxIndex && toggleClass(el, "uk-hidden", isNumeric(index$$1) && (this$1.sets && !includes(this$1.sets, toFloat(index$$1)) || index$$1 > this$1.maxIndex));
                });
            },
            events: ["resize"]
        },
        events: {
            beforeitemshow: function (e) {
                if (!this.dragging && this.sets && this.stack.length < 2 && !includes(this.sets, this.index)) {
                    this.index = this.getValidIndex();
                }
                var diff = Math.abs(this.index - this.prevIndex + (this.dir > 0 && this.index < this.prevIndex || this.dir < 0 && this.index > this.prevIndex ? (this.maxIndex + 1) * this.dir : 0));
                if (!this.dragging && diff > 1) {
                    for (var i = 0; i < diff; i++) {
                        this.stack.splice(1, 0, this.dir > 0 ? "next" : "previous");
                    }
                    e.preventDefault();
                    return;
                }
                this.duration = speedUp(this.avgWidth / this.velocity) * (bounds(this.dir < 0 || !this.slides[this.prevIndex] ? this.slides[this.index] : this.slides[this.prevIndex]).width / this.avgWidth);
                this.reorder();
            },
            itemshow: function () {
                !isUndefined(this.prevIndex) && addClass(this._getTransitioner().getItemIn(), this.clsActive);
            },
            itemshown: function () {
                var this$1 = this;
                var actives = this._getTransitioner(this.index).getActives();
                this.slides.forEach(function (slide) {
                    return toggleClass(slide, this$1.clsActive, includes(actives, slide));
                });
                (!this.sets || includes(this.sets, toFloat(this.index))) && this.slides.forEach(function (slide) {
                    return toggleClass(slide, this$1.clsActivated, includes(actives, slide));
                });
            }
        },
        methods: {
            reorder: function () {
                var this$1 = this;
                css(this.slides, "order", "");
                if (this.finite) {
                    return;
                }
                var index$$1 = this.dir > 0 && this.slides[this.prevIndex] ? this.prevIndex : this.index;
                this.slides.forEach(function (slide, i) {
                    return css(slide, "order", this$1.dir > 0 && i < index$$1 ? 1 : this$1.dir < 0 && i >= this$1.index ? -1 : "");
                });
                if (!this.center) {
                    return;
                }
                var next = this.slides[index$$1];
                var width$$1 = bounds(this.list).width / 2 - bounds(next).width / 2;
                var j = 0;
                while (width$$1 > 0) {
                    var slideIndex = this.getIndex(--j + index$$1, index$$1);
                    var slide = this.slides[slideIndex];
                    css(slide, "order", slideIndex > index$$1 ? -2 : -1);
                    width$$1 -= bounds(slide).width;
                }
            },
            getValidIndex: function (index$$1, prevIndex) {
                if (index$$1 === void 0) index$$1 = this.index;
                if (prevIndex === void 0) prevIndex = this.prevIndex;
                index$$1 = this.getIndex(index$$1, prevIndex);
                if (!this.sets) {
                    return index$$1;
                }
                var prev;
                do {
                    if (includes(this.sets, index$$1)) {
                        return index$$1;
                    }
                    prev = index$$1;
                    index$$1 = this.getIndex(index$$1 + this.dir, prevIndex);
                } while (index$$1 !== prev);
                return index$$1;
            }
        }
    };
    var SliderParallax = {
        mixins: [Parallax],
        data: {
            selItem: "!li"
        },
        computed: {
            item: function (ref, $el) {
                var selItem = ref.selItem;
                return query(selItem, $el);
            }
        },
        events: [{
            name: "itemshown",
            self: true,
            el: function () {
                return this.item;
            },
            handler: function () {
                css(this.$el, this.getCss(.5));
            }
        }, {
            name: "itemin itemout",
            self: true,
            el: function () {
                return this.item;
            },
            handler: function (ref) {
                var type = ref.type;
                var ref_detail = ref.detail;
                var percent = ref_detail.percent;
                var duration = ref_detail.duration;
                var timing = ref_detail.timing;
                var dir = ref_detail.dir;
                Transition.cancel(this.$el);
                css(this.$el, this.getCss(getCurrent(type, dir, percent)));
                Transition.start(this.$el, this.getCss(isIn(type) ? .5 : dir > 0 ? 1 : 0), duration, timing).catch(noop);
            }
        }, {
            name: "transitioncanceled transitionend",
            self: true,
            el: function () {
                return this.item;
            },
            handler: function () {
                Transition.cancel(this.$el);
            }
        }, {
            name: "itemtranslatein itemtranslateout",
            self: true,
            el: function () {
                return this.item;
            },
            handler: function (ref) {
                var type = ref.type;
                var ref_detail = ref.detail;
                var percent = ref_detail.percent;
                var dir = ref_detail.dir;
                Transition.cancel(this.$el);
                css(this.$el, this.getCss(getCurrent(type, dir, percent)));
            }
        }]
    };
    function isIn(type) {
        return endsWith(type, "in");
    }
    function getCurrent(type, dir, percent) {
        percent /= 2;
        return !isIn(type) ? dir < 0 ? percent : 1 - percent : dir < 0 ? 1 - percent : percent;
    }
    var Animations$2 = assign({}, Animations, {
        fade: {
            show: function () {
                return [{
                    opacity: 0,
                    zIndex: 0
                }, {
                    zIndex: -1
                }];
            },
            percent: function (current) {
                return 1 - css(current, "opacity");
            },
            translate: function (percent) {
                return [{
                    opacity: 1 - percent,
                    zIndex: 0
                }, {
                    zIndex: -1
                }];
            }
        },
        scale: {
            show: function () {
                return [{
                    opacity: 0,
                    transform: scale3d(1 + .5),
                    zIndex: 0
                }, {
                    zIndex: -1
                }];
            },
            percent: function (current) {
                return 1 - css(current, "opacity");
            },
            translate: function (percent) {
                return [{
                    opacity: 1 - percent,
                    transform: scale3d(1 + .5 * percent),
                    zIndex: 0
                }, {
                    zIndex: -1
                }];
            }
        },
        pull: {
            show: function (dir) {
                return dir < 0 ? [{
                    transform: translate(30),
                    zIndex: -1
                }, {
                    transform: translate(),
                    zIndex: 0
                }] : [{
                    transform: translate(-100),
                    zIndex: 0
                }, {
                    transform: translate(),
                    zIndex: -1
                }];
            },
            percent: function (current, next, dir) {
                return dir < 0 ? 1 - translated(next) : translated(current);
            },
            translate: function (percent, dir) {
                return dir < 0 ? [{
                    transform: translate(30 * percent),
                    zIndex: -1
                }, {
                    transform: translate(-100 * (1 - percent)),
                    zIndex: 0
                }] : [{
                    transform: translate(-percent * 100),
                    zIndex: 0
                }, {
                    transform: translate(30 * (1 - percent)),
                    zIndex: -1
                }];
            }
        },
        push: {
            show: function (dir) {
                return dir < 0 ? [{
                    transform: translate(100),
                    zIndex: 0
                }, {
                    transform: translate(),
                    zIndex: -1
                }] : [{
                    transform: translate(-30),
                    zIndex: -1
                }, {
                    transform: translate(),
                    zIndex: 0
                }];
            },
            percent: function (current, next, dir) {
                return dir > 0 ? 1 - translated(next) : translated(current);
            },
            translate: function (percent, dir) {
                return dir < 0 ? [{
                    transform: translate(percent * 100),
                    zIndex: 0
                }, {
                    transform: translate(-30 * (1 - percent)),
                    zIndex: -1
                }] : [{
                    transform: translate(-30 * percent),
                    zIndex: -1
                }, {
                    transform: translate(100 * (1 - percent)),
                    zIndex: 0
                }];
            }
        }
    });
    var Slideshow$1 = {
        mixins: [Class, Slideshow, SliderReactive],
        props: {
            ratio: String,
            minHeight: Boolean,
            maxHeight: Boolean
        },
        data: {
            ratio: "16:9",
            minHeight: false,
            maxHeight: false,
            selList: ".uk-slideshow-items",
            attrItem: "uk-slideshow-item",
            selNav: ".uk-slideshow-nav",
            Animations: Animations$2
        },
        update: {
            read: function () {
                var ref = this.ratio.split(":").map(Number);
                var width$$1 = ref[0];
                var height$$1 = ref[1];
                height$$1 = height$$1 * this.list.offsetWidth / width$$1;
                if (this.minHeight) {
                    height$$1 = Math.max(this.minHeight, height$$1);
                }
                if (this.maxHeight) {
                    height$$1 = Math.min(this.maxHeight, height$$1);
                }
                return {
                    height: height$$1 - boxModelAdjust(this.list, "content-box")
                };
            },
            write: function (ref) {
                var height$$1 = ref.height;
                css(this.list, "minHeight", height$$1);
            },
            events: ["resize"]
        }
    };
    var Sortable = {
        mixins: [Class, Animate],
        props: {
            group: String,
            threshold: Number,
            clsItem: String,
            clsPlaceholder: String,
            clsDrag: String,
            clsDragState: String,
            clsBase: String,
            clsNoDrag: String,
            clsEmpty: String,
            clsCustom: String,
            handle: String
        },
        data: {
            group: false,
            threshold: 5,
            clsItem: "uk-sortable-item",
            clsPlaceholder: "uk-sortable-placeholder",
            clsDrag: "uk-sortable-drag",
            clsDragState: "uk-drag",
            clsBase: "uk-sortable",
            clsNoDrag: "uk-sortable-nodrag",
            clsEmpty: "uk-sortable-empty",
            clsCustom: "",
            handle: false
        },
        created: function () {
            var this$1 = this;
            ["init", "start", "move", "end"].forEach(function (key) {
                var fn = this$1[key];
                this$1[key] = function (e) {
                    this$1.scrollY = window.pageYOffset;
                    var ref = getPos$1(e, "page");
                    var x = ref.x;
                    var y = ref.y;
                    this$1.pos = {
                        x: x,
                        y: y
                    };
                    fn(e);
                };
            });
        },
        events: {
            name: pointerDown,
            passive: false,
            handler: "init"
        },
        update: {
            write: function () {
                if (this.clsEmpty) {
                    toggleClass(this.$el, this.clsEmpty, !this.$el.children.length);
                }
                css(this.handle ? $$(this.handle, this.$el) : this.$el.children, "touchAction", "none");
                if (!this.drag) {
                    return;
                }
                offset(this.drag, {
                    top: this.pos.y + this.origin.top,
                    left: this.pos.x + this.origin.left
                });
                var ref = offset(this.drag);
                var top = ref.top;
                var offsetHeight = ref.height;
                var bottom = top + offsetHeight;
                var scroll;
                if (top > 0 && top < this.scrollY) {
                    scroll = this.scrollY - 5;
                } else if (bottom < height(document) && bottom > height(window) + this.scrollY) {
                    scroll = this.scrollY + 5;
                }
                scroll && setTimeout(function () {
                    return scrollTop(window, scroll);
                }, 5);
            }
        },
        methods: {
            init: function (e) {
                var target = e.target;
                var button = e.button;
                var defaultPrevented = e.defaultPrevented;
                var ref = toNodes(this.$el.children).filter(function (el) {
                    return within(target, el);
                });
                var placeholder = ref[0];
                if (!placeholder || isInput(target) || this.handle && !within(target, this.handle) || button > 0 || within(target, "." + this.clsNoDrag) || defaultPrevented) {
                    return;
                }
                e.preventDefault();
                this.touched = [this];
                this.placeholder = placeholder;
                this.origin = assign({
                    target: target,
                    index: index(placeholder)
                }, this.pos);
                on(document, pointerMove, this.move);
                on(document, pointerUp, this.end);
                on(window, "scroll", this.scroll);
                if (!this.threshold) {
                    this.start(e);
                }
            },
            start: function (e) {
                this.drag = append(this.$container, this.placeholder.outerHTML.replace(/^<li/i, "<div").replace(/li>$/i, "div>"));
                css(this.drag, assign({
                    boxSizing: "border-box",
                    width: this.placeholder.offsetWidth,
                    height: this.placeholder.offsetHeight
                }, css(this.placeholder, ["paddingLeft", "paddingRight", "paddingTop", "paddingBottom"])));
                attr(this.drag, "uk-no-boot", "");
                addClass(this.drag, this.clsDrag, this.clsCustom);
                height(this.drag.firstElementChild, height(this.placeholder.firstElementChild));
                var ref = offset(this.placeholder);
                var left = ref.left;
                var top = ref.top;
                assign(this.origin, {
                    left: left - this.pos.x,
                    top: top - this.pos.y
                });
                addClass(this.placeholder, this.clsPlaceholder);
                addClass(this.$el.children, this.clsItem);
                addClass(document.documentElement, this.clsDragState);
                trigger(this.$el, "start", [this, this.placeholder]);
                this.move(e);
            },
            move: function (e) {
                if (!this.drag) {
                    if (Math.abs(this.pos.x - this.origin.x) > this.threshold || Math.abs(this.pos.y - this.origin.y) > this.threshold) {
                        this.start(e);
                    }
                    return;
                }
                this.$emit();
                var target = e.type === "mousemove" ? e.target : document.elementFromPoint(this.pos.x - window.pageXOffset, this.pos.y - window.pageYOffset);
                var sortable = this.getSortable(target);
                var previous = this.getSortable(this.placeholder);
                var move = sortable !== previous;
                if (!sortable || within(target, this.placeholder) || move && (!sortable.group || sortable.group !== previous.group)) {
                    return;
                }
                target = sortable.$el === target.parentNode && target || toNodes(sortable.$el.children).filter(function (element) {
                    return within(target, element);
                })[0];
                if (move) {
                    previous.remove(this.placeholder);
                } else if (!target) {
                    return;
                }
                sortable.insert(this.placeholder, target);
                if (!includes(this.touched, sortable)) {
                    this.touched.push(sortable);
                }
            },
            end: function (e) {
                off(document, pointerMove, this.move);
                off(document, pointerUp, this.end);
                off(window, "scroll", this.scroll);
                if (!this.drag) {
                    if (e.type === "touchend") {
                        e.target.click();
                    }
                    return;
                }
                preventClick();
                var sortable = this.getSortable(this.placeholder);
                if (this === sortable) {
                    if (this.origin.index !== index(this.placeholder)) {
                        trigger(this.$el, "moved", [this, this.placeholder]);
                    }
                } else {
                    trigger(sortable.$el, "added", [sortable, this.placeholder]);
                    trigger(this.$el, "removed", [this, this.placeholder]);
                }
                trigger(this.$el, "stop", [this, this.placeholder]);
                remove(this.drag);
                this.drag = null;
                var classes = this.touched.map(function (sortable) {
                    return sortable.clsPlaceholder + " " + sortable.clsItem;
                }).join(" ");
                this.touched.forEach(function (sortable) {
                    return removeClass(sortable.$el.children, classes);
                });
                removeClass(document.documentElement, this.clsDragState);
            },
            scroll: function () {
                var scroll = window.pageYOffset;
                if (scroll !== this.scrollY) {
                    this.pos.y += scroll - this.scrollY;
                    this.scrollY = scroll;
                    this.$emit();
                }
            },
            insert: function (element, target) {
                var this$1 = this;
                addClass(this.$el.children, this.clsItem);
                var insert = function () {
                    if (target) {
                        if (!within(element, this$1.$el) || isPredecessor(element, target)) {
                            before(target, element);
                        } else {
                            after(target, element);
                        }
                    } else {
                        append(this$1.$el, element);
                    }
                };
                if (this.animation) {
                    this.animate(insert);
                } else {
                    insert();
                }
            },
            remove: function (element) {
                if (!within(element, this.$el)) {
                    return;
                }
                if (this.animation) {
                    this.animate(function () {
                        return remove(element);
                    });
                } else {
                    remove(element);
                }
            },
            getSortable: function (element) {
                return element && (this.$getComponent(element, "sortable") || this.getSortable(element.parentNode));
            }
        }
    };
    function isPredecessor(element, target) {
        return element.parentNode === target.parentNode && index(element) > index(target);
    }
    var obj$1;
    var actives = [];
    var Tooltip = {
        mixins: [Container, Togglable, Position],
        args: "title",
        props: {
            delay: Number,
            title: String
        },
        data: {
            pos: "top",
            title: "",
            delay: 0,
            animation: ["uk-animation-scale-up"],
            duration: 100,
            cls: "uk-active",
            clsPos: "uk-tooltip"
        },
        beforeConnect: function () {
            this._hasTitle = hasAttr(this.$el, "title");
            attr(this.$el, {
                title: "",
                "aria-expanded": false
            });
        },
        disconnected: function () {
            this.hide();
            attr(this.$el, {
                title: this._hasTitle ? this.title : null,
                "aria-expanded": null
            });
        },
        methods: {
            show: function () {
                var this$1 = this;
                if (includes(actives, this)) {
                    return;
                }
                actives.forEach(function (active) {
                    return active.hide();
                });
                actives.push(this);
                this._unbind = on(document, pointerUp, function (e) {
                    return !within(e.target, this$1.$el) && this$1.hide();
                });
                clearTimeout(this.showTimer);
                this.showTimer = setTimeout(function () {
                    this$1._show();
                    this$1.hideTimer = setInterval(function () {
                        if (!isVisible(this$1.$el)) {
                            this$1.hide();
                        }
                    }, 150);
                }, this.delay);
            },
            hide: function () {
                var index$$1 = actives.indexOf(this);
                if (!~index$$1 || matches(this.$el, "input") && this.$el === document.activeElement) {
                    return;
                }
                actives.splice(index$$1, 1);
                clearTimeout(this.showTimer);
                clearInterval(this.hideTimer);
                attr(this.$el, "aria-expanded", false);
                this.toggleElement(this.tooltip, false);
                this.tooltip && remove(this.tooltip);
                this.tooltip = false;
                this._unbind();
            },
            _show: function () {
                this.tooltip = append(this.container, '<div class="' + this.clsPos + '" aria-expanded="true" aria-hidden> <div class="' + this.clsPos + '-inner">' + this.title + "</div> </div>");
                this.positionAt(this.tooltip, this.$el);
                this.origin = this.getAxis() === "y" ? flipPosition(this.dir) + "-" + this.align : this.align + "-" + flipPosition(this.dir);
                this.toggleElement(this.tooltip, true);
            }
        },
        events: (obj$1 = {}, obj$1["focus " + pointerEnter + " " + pointerDown] = function (e) {
            if (e.type !== pointerDown || !isTouch(e)) {
                this.show();
            }
        }, obj$1.blur = "hide", obj$1[pointerLeave] = function (e) {
            if (!isTouch(e)) {
                this.hide();
            }
        }, obj$1)
    };
    var Upload = {
        props: {
            allow: String,
            clsDragover: String,
            concurrent: Number,
            maxSize: Number,
            method: String,
            mime: String,
            msgInvalidMime: String,
            msgInvalidName: String,
            msgInvalidSize: String,
            multiple: Boolean,
            name: String,
            params: Object,
            type: String,
            url: String
        },
        data: {
            allow: false,
            clsDragover: "uk-dragover",
            concurrent: 1,
            maxSize: 0,
            method: "POST",
            mime: false,
            msgInvalidMime: "Invalid File Type: %s",
            msgInvalidName: "Invalid File Name: %s",
            msgInvalidSize: "Invalid File Size: %s Kilobytes Max",
            multiple: false,
            name: "files[]",
            params: {},
            type: "",
            url: "",
            abort: noop,
            beforeAll: noop,
            beforeSend: noop,
            complete: noop,
            completeAll: noop,
            error: noop,
            fail: noop,
            load: noop,
            loadEnd: noop,
            loadStart: noop,
            progress: noop
        },
        events: {
            change: function (e) {
                if (!matches(e.target, 'input[type="file"]')) {
                    return;
                }
                e.preventDefault();
                if (e.target.files) {
                    this.upload(e.target.files);
                }
                e.target.value = "";
            },
            drop: function (e) {
                stop(e);
                var transfer = e.dataTransfer;
                if (!transfer || !transfer.files) {
                    return;
                }
                removeClass(this.$el, this.clsDragover);
                this.upload(transfer.files);
            },
            dragenter: function (e) {
                stop(e);
            },
            dragover: function (e) {
                stop(e);
                addClass(this.$el, this.clsDragover);
            },
            dragleave: function (e) {
                stop(e);
                removeClass(this.$el, this.clsDragover);
            }
        },
        methods: {
            upload: function (files) {
                var this$1 = this;
                if (!files.length) {
                    return;
                }
                trigger(this.$el, "upload", [files]);
                for (var i = 0; i < files.length; i++) {
                    if (this.maxSize && this.maxSize * 1e3 < files[i].size) {
                        this.fail(this.msgInvalidSize.replace("%s", this.maxSize));
                        return;
                    }
                    if (this.allow && !match$1(this.allow, files[i].name)) {
                        this.fail(this.msgInvalidName.replace("%s", this.allow));
                        return;
                    }
                    if (this.mime && !match$1(this.mime, files[i].type)) {
                        this.fail(this.msgInvalidMime.replace("%s", this.mime));
                        return;
                    }
                }
                if (!this.multiple) {
                    files = [files[0]];
                }
                this.beforeAll(this, files);
                var chunks = chunk(files, this.concurrent);
                var upload = function (files) {
                    var data$$1 = new FormData();
                    files.forEach(function (file) {
                        return data$$1.append(this$1.name, file);
                    });
                    for (var key in this$1.params) {
                        data$$1.append(key, this$1.params[key]);
                    }
                    ajax(this$1.url, {
                        data: data$$1,
                        method: this$1.method,
                        responseType: this$1.type,
                        beforeSend: function (env) {
                            var xhr = env.xhr;
                            xhr.upload && on(xhr.upload, "progress", this$1.progress);
                            ["loadStart", "load", "loadEnd", "abort"].forEach(function (type) {
                                return on(xhr, type.toLowerCase(), this$1[type]);
                            });
                            this$1.beforeSend(env);
                        }
                    }).then(function (xhr) {
                        this$1.complete(xhr);
                        if (chunks.length) {
                            upload(chunks.shift());
                        } else {
                            this$1.completeAll(xhr);
                        }
                    }, function (e) {
                        return this$1.error(e);
                    });
                };
                upload(chunks.shift());
            }
        }
    };
    function match$1(pattern, path) {
        return path.match(new RegExp("^" + pattern.replace(/\//g, "\\/").replace(/\*\*/g, "(\\/[^\\/]+)*").replace(/\*/g, "[^\\/]+").replace(/((?!\\))\?/g, "$1.") + "$", "i"));
    }
    function chunk(files, size) {
        var chunks = [];
        for (var i = 0; i < files.length; i += size) {
            var chunk = [];
            for (var j = 0; j < size; j++) {
                chunk.push(files[i + j]);
            }
            chunks.push(chunk);
        }
        return chunks;
    }
    function stop(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    UIkit.component("countdown", Countdown);
    UIkit.component("filter", Filter);
    UIkit.component("lightbox", Lightbox);
    UIkit.component("lightboxPanel", LightboxPanel);
    UIkit.component("notification", Notification);
    UIkit.component("parallax", Parallax$1);
    UIkit.component("slider", Slider$1);
    UIkit.component("sliderParallax", SliderParallax);
    UIkit.component("slideshow", Slideshow$1);
    UIkit.component("slideshowParallax", SliderParallax);
    UIkit.component("sortable", Sortable);
    UIkit.component("tooltip", Tooltip);
    UIkit.component("upload", Upload);
    {
        boot(UIkit);
    }
    return UIkit;
});

(function (global, factory) {
    typeof exports === "object" && typeof module !== "undefined" ? module.exports = factory() : typeof define === "function" && define.amd ? define("uikiticons", factory) : (global = global || self,
        global.UIkitIcons = factory());
})(this, function () {
    "use strict";
    function plugin(UIkit) {
        if (plugin.installed) {
            return;
        }
        UIkit.icon.add({
            "500px": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M9.624,11.866c-0.141,0.132,0.479,0.658,0.662,0.418c0.051-0.046,0.607-0.61,0.662-0.664c0,0,0.738,0.719,0.814,0.719 c0.1,0,0.207-0.055,0.322-0.17c0.27-0.269,0.135-0.416,0.066-0.495l-0.631-0.616l0.658-0.668c0.146-0.156,0.021-0.314-0.1-0.449 c-0.182-0.18-0.359-0.226-0.471-0.125l-0.656,0.654l-0.654-0.654c-0.033-0.034-0.08-0.045-0.124-0.045 c-0.079,0-0.191,0.068-0.307,0.181c-0.202,0.202-0.247,0.351-0.133,0.462l0.665,0.665L9.624,11.866z"/><path d="M11.066,2.884c-1.061,0-2.185,0.248-3.011,0.604c-0.087,0.034-0.141,0.106-0.15,0.205C7.893,3.784,7.919,3.909,7.982,4.066 c0.05,0.136,0.187,0.474,0.452,0.372c0.844-0.326,1.779-0.507,2.633-0.507c0.963,0,1.9,0.191,2.781,0.564 c0.695,0.292,1.357,0.719,2.078,1.34c0.051,0.044,0.105,0.068,0.164,0.068c0.143,0,0.273-0.137,0.389-0.271 c0.191-0.214,0.324-0.395,0.135-0.575c-0.686-0.654-1.436-1.138-2.363-1.533C13.24,3.097,12.168,2.884,11.066,2.884z"/><path d="M16.43,15.747c-0.092-0.028-0.242,0.05-0.309,0.119l0,0c-0.652,0.652-1.42,1.169-2.268,1.521 c-0.877,0.371-1.814,0.551-2.779,0.551c-0.961,0-1.896-0.189-2.775-0.564c-0.848-0.36-1.612-0.879-2.268-1.53 c-0.682-0.688-1.196-1.455-1.529-2.268c-0.325-0.799-0.471-1.643-0.471-1.643c-0.045-0.24-0.258-0.249-0.567-0.203 c-0.128,0.021-0.519,0.079-0.483,0.36v0.01c0.105,0.644,0.289,1.284,0.545,1.895c0.417,0.969,1.002,1.849,1.756,2.604 c0.757,0.754,1.636,1.34,2.604,1.757C8.901,18.785,9.97,19,11.088,19c1.104,0,2.186-0.215,3.188-0.645 c1.838-0.896,2.604-1.757,2.604-1.757c0.182-0.204,0.227-0.317-0.1-0.643C16.779,15.956,16.525,15.774,16.43,15.747z"/><path d="M5.633,13.287c0.293,0.71,0.723,1.341,1.262,1.882c0.54,0.54,1.172,0.971,1.882,1.264c0.731,0.303,1.509,0.461,2.298,0.461 c0.801,0,1.578-0.158,2.297-0.461c0.711-0.293,1.344-0.724,1.883-1.264c0.543-0.541,0.971-1.172,1.264-1.882 c0.314-0.721,0.463-1.5,0.463-2.298c0-0.79-0.148-1.569-0.463-2.289c-0.293-0.699-0.721-1.329-1.264-1.881 c-0.539-0.541-1.172-0.959-1.867-1.263c-0.721-0.303-1.5-0.461-2.299-0.461c-0.802,0-1.613,0.159-2.322,0.461 c-0.577,0.25-1.544,0.867-2.119,1.454v0.012V2.108h8.16C15.1,2.104,15.1,1.69,15.1,1.552C15.1,1.417,15.1,1,14.809,1H5.915 C5.676,1,5.527,1.192,5.527,1.384v6.84c0,0.214,0.273,0.372,0.529,0.428c0.5,0.105,0.614-0.056,0.737-0.224l0,0 c0.18-0.273,0.776-0.884,0.787-0.894c0.901-0.905,2.117-1.408,3.416-1.408c1.285,0,2.5,0.501,3.412,1.408 c0.914,0.914,1.408,2.122,1.408,3.405c0,1.288-0.508,2.496-1.408,3.405c-0.9,0.896-2.152,1.406-3.438,1.406 c-0.877,0-1.711-0.229-2.433-0.671v-4.158c0-0.553,0.237-1.151,0.643-1.614c0.462-0.519,1.094-0.799,1.782-0.799 c0.664,0,1.293,0.253,1.758,0.715c0.459,0.459,0.709,1.071,0.709,1.723c0,1.385-1.094,2.468-2.488,2.468 c-0.273,0-0.769-0.121-0.781-0.125c-0.281-0.087-0.405,0.306-0.438,0.436c-0.159,0.496,0.079,0.585,0.123,0.607 c0.452,0.137,0.743,0.157,1.129,0.157c1.973,0,3.572-1.6,3.572-3.57c0-1.964-1.6-3.552-3.572-3.552c-0.97,0-1.872,0.36-2.546,1.038 c-0.656,0.631-1.027,1.487-1.027,2.322v3.438v-0.011c-0.372-0.42-0.732-1.041-0.981-1.682c-0.102-0.248-0.315-0.202-0.607-0.113 c-0.135,0.035-0.519,0.157-0.44,0.439C5.372,12.799,5.577,13.164,5.633,13.287z"/></svg>',
            album: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect x="5" y="2" width="10" height="1"/><rect x="3" y="4" width="14" height="1"/><rect fill="none" stroke="#000" x="1.5" y="6.5" width="17" height="11"/></svg>',
            "arrow-down": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="10.5,16.08 5.63,10.66 6.37,10 10.5,14.58 14.63,10 15.37,10.66"/><line fill="none" stroke="#000" x1="10.5" y1="4" x2="10.5" y2="15"/></svg>',
            "arrow-left": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" points="10 14 5 9.5 10 5"/><line fill="none" stroke="#000" x1="16" y1="9.5" x2="5" y2="9.52"/></svg>',
            "arrow-right": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" points="10 5 15 9.5 10 14"/><line fill="none" stroke="#000" x1="4" y1="9.5" x2="15" y2="9.5"/></svg>',
            "arrow-up": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="10.5,4 15.37,9.4 14.63,10.08 10.5,5.49 6.37,10.08 5.63,9.4"/><line fill="none" stroke="#000" x1="10.5" y1="16" x2="10.5" y2="5"/></svg>',
            ban: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.1" cx="10" cy="10" r="9"/><line fill="none" stroke="#000" stroke-width="1.1" x1="4" y1="3.5" x2="16" y2="16.5"/></svg>',
            behance: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M9.5,10.6c-0.4-0.5-0.9-0.9-1.6-1.1c1.7-1,2.2-3.2,0.7-4.7C7.8,4,6.3,4,5.2,4C3.5,4,1.7,4,0,4v12c1.7,0,3.4,0,5.2,0 c1,0,2.1,0,3.1-0.5C10.2,14.6,10.5,12.3,9.5,10.6L9.5,10.6z M5.6,6.1c1.8,0,1.8,2.7-0.1,2.7c-1,0-2,0-2.9,0V6.1H5.6z M2.6,13.8v-3.1 c1.1,0,2.1,0,3.2,0c2.1,0,2.1,3.2,0.1,3.2L2.6,13.8z"/><path d="M19.9,10.9C19.7,9.2,18.7,7.6,17,7c-4.2-1.3-7.3,3.4-5.3,7.1c0.9,1.7,2.8,2.3,4.7,2.1c1.7-0.2,2.9-1.3,3.4-2.9h-2.2 c-0.4,1.3-2.4,1.5-3.5,0.6c-0.4-0.4-0.6-1.1-0.6-1.7H20C20,11.7,19.9,10.9,19.9,10.9z M13.5,10.6c0-1.6,2.3-2.7,3.5-1.4 c0.4,0.4,0.5,0.9,0.6,1.4H13.5L13.5,10.6z"/><rect x="13" y="4" width="5" height="1.4"/></svg>',
            bell: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" stroke-width="1.1" d="M17,15.5 L3,15.5 C2.99,14.61 3.79,13.34 4.1,12.51 C4.58,11.3 4.72,10.35 5.19,7.01 C5.54,4.53 5.89,3.2 7.28,2.16 C8.13,1.56 9.37,1.5 9.81,1.5 L9.96,1.5 C9.96,1.5 11.62,1.41 12.67,2.17 C14.08,3.2 14.42,4.54 14.77,7.02 C15.26,10.35 15.4,11.31 15.87,12.52 C16.2,13.34 17.01,14.61 17,15.5 L17,15.5 Z"/><path fill="none" stroke="#000" d="M12.39,16 C12.39,17.37 11.35,18.43 9.91,18.43 C8.48,18.43 7.42,17.37 7.42,16"/></svg>',
            bold: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M5,15.3 C5.66,15.3 5.9,15 5.9,14.53 L5.9,5.5 C5.9,4.92 5.56,4.7 5,4.7 L5,4 L8.95,4 C12.6,4 13.7,5.37 13.7,6.9 C13.7,7.87 13.14,9.17 10.86,9.59 L10.86,9.7 C13.25,9.86 14.29,11.28 14.3,12.54 C14.3,14.47 12.94,16 9,16 L5,16 L5,15.3 Z M9,9.3 C11.19,9.3 11.8,8.5 11.85,7 C11.85,5.65 11.3,4.8 9,4.8 L7.67,4.8 L7.67,9.3 L9,9.3 Z M9.185,15.22 C11.97,15 12.39,14 12.4,12.58 C12.4,11.15 11.39,10 9,10 L7.67,10 L7.67,15 L9.18,15 Z"/></svg>',
            bolt: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M4.74,20 L7.73,12 L3,12 L15.43,1 L12.32,9 L17.02,9 L4.74,20 L4.74,20 L4.74,20 Z M9.18,11 L7.1,16.39 L14.47,10 L10.86,10 L12.99,4.67 L5.61,11 L9.18,11 L9.18,11 L9.18,11 Z"/></svg>',
            bookmark: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon fill="none" stroke="#000" points="5.5 1.5 15.5 1.5 15.5 17.5 10.5 12.5 5.5 17.5"/></svg>',
            calendar: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M 2,3 2,17 18,17 18,3 2,3 Z M 17,16 3,16 3,8 17,8 17,16 Z M 17,7 3,7 3,4 17,4 17,7 Z"/><rect width="1" height="3" x="6" y="2"/><rect width="1" height="3" x="13" y="2"/></svg>',
            camera: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.1" cx="10" cy="10.8" r="3.8"/><path fill="none" stroke="#000" d="M1,4.5 C0.7,4.5 0.5,4.7 0.5,5 L0.5,17 C0.5,17.3 0.7,17.5 1,17.5 L19,17.5 C19.3,17.5 19.5,17.3 19.5,17 L19.5,5 C19.5,4.7 19.3,4.5 19,4.5 L13.5,4.5 L13.5,2.9 C13.5,2.6 13.3,2.5 13,2.5 L7,2.5 C6.7,2.5 6.5,2.6 6.5,2.9 L6.5,4.5 L1,4.5 L1,4.5 Z"/></svg>',
            cart: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle cx="7.3" cy="17.3" r="1.4"/><circle cx="13.3" cy="17.3" r="1.4"/><polyline fill="none" stroke="#000" points="0 2 3.2 4 5.3 12.5 16 12.5 18 6.5 8 6.5"/></svg>',
            check: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="1.1" points="4,10 8,15 17,4"/></svg>',
            "chevron-double-left": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="1.03" points="10 14 6 10 10 6"/><polyline fill="none" stroke="#000" stroke-width="1.03" points="14 14 10 10 14 6"/></svg>',
            "chevron-double-right": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="1.03" points="10 6 14 10 10 14"/><polyline fill="none" stroke="#000" stroke-width="1.03" points="6 6 10 10 6 14"/></svg>',
            "chevron-down": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="1.03" points="16 7 10 13 4 7"/></svg>',
            "chevron-left": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="1.03" points="13 16 7 10 13 4"/></svg>',
            "chevron-right": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="1.03" points="7 4 13 10 7 16"/></svg>',
            "chevron-up": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="1.03" points="4 13 10 7 16 13"/></svg>',
            clock: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.1" cx="10" cy="10" r="9"/><rect x="9" y="4" width="1" height="7"/><path fill="none" stroke="#000" stroke-width="1.1" d="M13.018,14.197 L9.445,10.625"/></svg>',
            close: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" stroke-width="1.06" d="M16,16 L4,4"/><path fill="none" stroke="#000" stroke-width="1.06" d="M16,4 L4,16"/></svg>',
            "cloud-download": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" stroke-width="1.1" d="M6.5,14.61 L3.75,14.61 C1.96,14.61 0.5,13.17 0.5,11.39 C0.5,9.76 1.72,8.41 3.3,8.2 C3.38,5.31 5.75,3 8.68,3 C11.19,3 13.31,4.71 13.89,7.02 C14.39,6.8 14.93,6.68 15.5,6.68 C17.71,6.68 19.5,8.45 19.5,10.64 C19.5,12.83 17.71,14.6 15.5,14.6 L12.5,14.6"/><polyline fill="none" stroke="#000" points="11.75 16 9.5 18.25 7.25 16"/><path fill="none" stroke="#000" d="M9.5,18 L9.5,9.5"/></svg>',
            "cloud-upload": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" stroke-width="1.1" d="M6.5,14.61 L3.75,14.61 C1.96,14.61 0.5,13.17 0.5,11.39 C0.5,9.76 1.72,8.41 3.31,8.2 C3.38,5.31 5.75,3 8.68,3 C11.19,3 13.31,4.71 13.89,7.02 C14.39,6.8 14.93,6.68 15.5,6.68 C17.71,6.68 19.5,8.45 19.5,10.64 C19.5,12.83 17.71,14.6 15.5,14.6 L12.5,14.6"/><polyline fill="none" stroke="#000" points="7.25 11.75 9.5 9.5 11.75 11.75"/><path fill="none" stroke="#000" d="M9.5,18 L9.5,9.5"/></svg>',
            code: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" stroke-width="1.01" points="13,4 19,10 13,16"/><polyline fill="none" stroke="#000" stroke-width="1.01" points="7,4 1,10 7,16"/></svg>',
            cog: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" cx="9.997" cy="10" r="3.31"/><path fill="none" stroke="#000" d="M18.488,12.285 L16.205,16.237 C15.322,15.496 14.185,15.281 13.303,15.791 C12.428,16.289 12.047,17.373 12.246,18.5 L7.735,18.5 C7.938,17.374 7.553,16.299 6.684,15.791 C5.801,15.27 4.655,15.492 3.773,16.237 L1.5,12.285 C2.573,11.871 3.317,10.999 3.317,9.991 C3.305,8.98 2.573,8.121 1.5,7.716 L3.765,3.784 C4.645,4.516 5.794,4.738 6.687,4.232 C7.555,3.722 7.939,2.637 7.735,1.5 L12.263,1.5 C12.072,2.637 12.441,3.71 13.314,4.22 C14.206,4.73 15.343,4.516 16.225,3.794 L18.487,7.714 C17.404,8.117 16.661,8.988 16.67,10.009 C16.672,11.018 17.415,11.88 18.488,12.285 L18.488,12.285 Z"/></svg>',
            aws: '<svg width="24" height="24" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M6.763 10.036c0 .296.032.535.088.71.064.176.144.368.256.576.04.063.056.127.056.183 0 .08-.048.16-.152.24l-.503.335a.383.383 0 0 1-.208.072c-.08 0-.16-.04-.239-.112a2.47 2.47 0 0 1-.287-.375 6.18 6.18 0 0 1-.248-.471c-.622.734-1.405 1.101-2.347 1.101-.67 0-1.205-.191-1.596-.574-.391-.384-.59-.894-.59-1.533 0-.678.239-1.23.726-1.644.487-.415 1.133-.623 1.955-.623.272 0 .551.024.846.064.296.04.6.104.918.176v-.583c0-.607-.127-1.03-.375-1.277-.255-.248-.686-.367-1.3-.367-.28 0-.568.031-.863.103-.295.072-.583.16-.862.272a2.287 2.287 0 0 1-.28.104.488.488 0 0 1-.127.023c-.112 0-.168-.08-.168-.247v-.391c0-.128.016-.224.056-.28a.597.597 0 0 1 .224-.167c.279-.144.614-.264 1.005-.36a4.84 4.84 0 0 1 1.246-.151c.95 0 1.644.216 2.091.647.439.43.662 1.085.662 1.963v2.586zm-3.24 1.214c.263 0 .534-.048.822-.144.287-.096.543-.271.758-.51.128-.152.224-.32.272-.512.047-.191.08-.423.08-.694v-.335a6.66 6.66 0 0 0-.735-.136 6.02 6.02 0 0 0-.75-.048c-.535 0-.926.104-1.19.32-.263.215-.39.518-.39.917 0 .375.095.655.295.846.191.2.47.296.838.296zm6.41.862c-.144 0-.24-.024-.304-.08-.064-.048-.12-.16-.168-.311L7.586 5.55a1.398 1.398 0 0 1-.072-.32c0-.128.064-.2.191-.2h.783c.151 0 .255.025.31.08.065.048.113.16.16.312l1.342 5.284 1.245-5.284c.04-.16.088-.264.151-.312a.549.549 0 0 1 .32-.08h.638c.152 0 .256.025.32.08.063.048.12.16.151.312l1.261 5.348 1.381-5.348c.048-.16.104-.264.16-.312a.52.52 0 0 1 .311-.08h.743c.127 0 .2.065.2.2 0 .04-.009.08-.017.128a1.137 1.137 0 0 1-.056.2l-1.923 6.17c-.048.16-.104.263-.168.311a.51.51 0 0 1-.303.08h-.687c-.151 0-.255-.024-.32-.08-.063-.056-.119-.16-.15-.32l-1.238-5.148-1.23 5.14c-.04.16-.087.264-.15.32-.065.056-.177.08-.32.08zm10.256.215c-.415 0-.83-.048-1.229-.143-.399-.096-.71-.2-.918-.32-.128-.071-.215-.151-.247-.223a.563.563 0 0 1-.048-.224v-.407c0-.167.064-.247.183-.247.048 0 .096.008.144.024.048.016.12.048.2.08.271.12.566.215.878.279.319.064.63.096.95.096.502 0 .894-.088 1.165-.264a.86.86 0 0 0 .415-.758.777.777 0 0 0-.215-.559c-.144-.151-.416-.287-.807-.415l-1.157-.36c-.583-.183-1.014-.454-1.277-.813a1.902 1.902 0 0 1-.4-1.158c0-.335.073-.63.216-.886.144-.255.335-.479.575-.654.24-.184.51-.32.83-.415.32-.096.655-.136 1.006-.136.175 0 .359.008.535.032.183.024.35.056.518.088.16.04.312.08.455.127.144.048.256.096.336.144a.69.69 0 0 1 .24.2.43.43 0 0 1 .071.263v.375c0 .168-.064.256-.184.256a.83.83 0 0 1-.303-.096 3.652 3.652 0 0 0-1.532-.311c-.455 0-.815.071-1.062.223-.248.152-.375.383-.375.71 0 .224.08.416.24.567.159.152.454.304.877.44l1.134.358c.574.184.99.44 1.237.767.247.327.367.702.367 1.117 0 .343-.072.655-.207.926-.144.272-.336.511-.583.703-.248.2-.543.343-.886.447-.36.111-.734.167-1.142.167zM21.698 16.207c-2.626 1.94-6.442 2.969-9.722 2.969-4.598 0-8.74-1.7-11.87-4.526-.247-.223-.024-.527.272-.351 3.384 1.963 7.559 3.153 11.877 3.153 2.914 0 6.114-.607 9.06-1.852.439-.2.814.287.383.607zM22.792 14.961c-.336-.43-2.22-.207-3.074-.103-.255.032-.295-.192-.063-.36 1.5-1.053 3.967-.75 4.254-.399.287.36-.08 2.826-1.485 4.007-.215.184-.423.088-.327-.151.32-.79 1.03-2.57.695-2.994z"/></svg>',
            azure: '<svg width="24" height="24" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><title>Azure DevOps icon</title><path d="M0 8.877L2.247 5.91l8.405-3.416V.022l7.37 5.393L2.966 8.338v8.225L0 15.707zm24-4.45v14.651l-5.753 4.9-9.303-3.057v3.056l-5.978-7.416 15.057 1.798V5.415z"/></svg>',
            gcp: '<svg width="24" height="24" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><title>Google Cloud icon</title><path d="M12.19 2.38a9.344 9.344 0 0 0-9.234 6.893c.053-.02-.055.013 0 0-3.875 2.551-3.922 8.11-.247 10.941l.006-.007-.007.03a6.717 6.717 0 0 0 4.077 1.356h5.173l.03.03h5.192c6.687.053 9.376-8.605 3.835-12.35a9.365 9.365 0 0 0-2.821-4.552l-.043.043.006-.05A9.344 9.344 0 0 0 12.19 2.38zm-.358 4.146c1.244-.04 2.518.368 3.486 1.15a5.186 5.186 0 0 1 1.862 4.078v.518c3.53-.07 3.53 5.262 0 5.193h-5.193l-.008.009v-.04H6.785a2.59 2.59 0 0 1-1.067-.23h.001a2.597 2.597 0 1 1 3.437-3.437l3.013-3.012A6.747 6.747 0 0 0 8.11 8.24c.018-.01.04-.026.054-.023a5.186 5.186 0 0 1 3.67-1.69z"/></svg>',
            comment: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M6,18.71 L6,14 L1,14 L1,1 L19,1 L19,14 L10.71,14 L6,18.71 L6,18.71 Z M2,13 L7,13 L7,16.29 L10.29,13 L18,13 L18,2 L2,2 L2,13 L2,13 Z"/></svg>',
            commenting: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon fill="none" stroke="#000" points="1.5,1.5 18.5,1.5 18.5,13.5 10.5,13.5 6.5,17.5 6.5,13.5 1.5,13.5"/><circle cx="10" cy="8" r="1"/><circle cx="6" cy="8" r="1"/><circle cx="14" cy="8" r="1"/></svg>',
            comments: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" points="2 0.5 19.5 0.5 19.5 13"/><path d="M5,19.71 L5,15 L0,15 L0,2 L18,2 L18,15 L9.71,15 L5,19.71 L5,19.71 L5,19.71 Z M1,14 L6,14 L6,17.29 L9.29,14 L17,14 L17,3 L1,3 L1,14 L1,14 L1,14 Z"/></svg>',
            copy: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect fill="none" stroke="#000" x="3.5" y="2.5" width="12" height="16"/><polyline fill="none" stroke="#000" points="5 0.5 17.5 0.5 17.5 17"/></svg>',
            "credit-card": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect fill="none" stroke="#000" x="1.5" y="4.5" width="17" height="12"/><rect x="1" y="7" width="18" height="3"/></svg>',
            database: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><ellipse fill="none" stroke="#000" cx="10" cy="4.64" rx="7.5" ry="3.14"/><path fill="none" stroke="#000" d="M17.5,8.11 C17.5,9.85 14.14,11.25 10,11.25 C5.86,11.25 2.5,9.84 2.5,8.11"/><path fill="none" stroke="#000" d="M17.5,11.25 C17.5,12.99 14.14,14.39 10,14.39 C5.86,14.39 2.5,12.98 2.5,11.25"/><path fill="none" stroke="#000" d="M17.49,4.64 L17.5,14.36 C17.5,16.1 14.14,17.5 10,17.5 C5.86,17.5 2.5,16.09 2.5,14.36 L2.5,4.64"/></svg>',
            desktop: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect x="8" y="15" width="1" height="2"/><rect x="11" y="15" width="1" height="2"/><rect x="5" y="16" width="10" height="1"/><rect fill="none" stroke="#000" x="1.5" y="3.5" width="17" height="11"/></svg>',
            download: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" points="14,10 9.5,14.5 5,10"/><rect x="3" y="17" width="13" height="1"/><line fill="none" stroke="#000" x1="9.5" y1="13.91" x2="9.5" y2="3"/></svg>',
            dribbble: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" stroke-width="1.4" d="M1.3,8.9c0,0,5,0.1,8.6-1c1.4-0.4,2.6-0.9,4-1.9 c1.4-1.1,2.5-2.5,2.5-2.5"/><path fill="none" stroke="#000" stroke-width="1.4" d="M3.9,16.6c0,0,1.7-2.8,3.5-4.2 c1.8-1.3,4-2,5.7-2.2C16,10,19,10.6,19,10.6"/><path fill="none" stroke="#000" stroke-width="1.4" d="M6.9,1.6c0,0,3.3,4.6,4.2,6.8 c0.4,0.9,1.3,3.1,1.9,5.2c0.6,2,0.9,4.4,0.9,4.4"/><circle fill="none" stroke="#000" stroke-width="1.4" cx="10" cy="10" r="9"/></svg>',
            expand: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="13 2 18 2 18 7 17 7 17 3 13 3"/><polygon points="2 13 3 13 3 17 7 17 7 18 2 18"/><path fill="none" stroke="#000" stroke-width="1.1" d="M11,9 L17,3"/><path fill="none" stroke="#000" stroke-width="1.1" d="M3,17 L9,11"/></svg>',
            facebook: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M11,10h2.6l0.4-3H11V5.3c0-0.9,0.2-1.5,1.5-1.5H14V1.1c-0.3,0-1-0.1-2.1-0.1C9.6,1,8,2.4,8,5v2H5.5v3H8v8h3V10z"/></svg>',
            "file-edit": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" d="M18.65,1.68 C18.41,1.45 18.109,1.33 17.81,1.33 C17.499,1.33 17.209,1.45 16.98,1.68 L8.92,9.76 L8,12.33 L10.55,11.41 L18.651,3.34 C19.12,2.87 19.12,2.15 18.65,1.68 L18.65,1.68 L18.65,1.68 Z"/><polyline fill="none" stroke="#000" points="16.5 8.482 16.5 18.5 3.5 18.5 3.5 1.5 14.211 1.5"/></svg>',
            "file-pdf": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect fill="none" stroke="#000" width="13" height="17" x="3.5" y="1.5"/><path d="M14.65 11.67c-.48.3-1.37-.19-1.79-.37a4.65 4.65 0 0 1 1.49.06c.35.1.36.28.3.31zm-6.3.06l.43-.79a14.7 14.7 0 0 0 .75-1.64 5.48 5.48 0 0 0 1.25 1.55l.2.15a16.36 16.36 0 0 0-2.63.73zM9.5 5.32c.2 0 .32.5.32.97a1.99 1.99 0 0 1-.23 1.04 5.05 5.05 0 0 1-.17-1.3s0-.71.08-.71zm-3.9 9a4.35 4.35 0 0 1 1.21-1.46l.24-.22a4.35 4.35 0 0 1-1.46 1.68zm9.23-3.3a2.05 2.05 0 0 0-1.32-.3 11.07 11.07 0 0 0-1.58.11 4.09 4.09 0 0 1-.74-.5 5.39 5.39 0 0 1-1.32-2.06 10.37 10.37 0 0 0 .28-2.62 1.83 1.83 0 0 0-.07-.25.57.57 0 0 0-.52-.4H9.4a.59.59 0 0 0-.6.38 6.95 6.95 0 0 0 .37 3.14c-.26.63-1 2.12-1 2.12-.3.58-.57 1.08-.82 1.5l-.8.44A3.11 3.11 0 0 0 5 14.16a.39.39 0 0 0 .15.42l.24.13c1.15.56 2.28-1.74 2.66-2.42a23.1 23.1 0 0 1 3.59-.85 4.56 4.56 0 0 0 2.91.8.5.5 0 0 0 .3-.21 1.1 1.1 0 0 0 .12-.75.84.84 0 0 0-.14-.25z"/></svg>',
            "file-text": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect fill="none" stroke="#000" width="13" height="17" x="3.5" y="1.5"/><line fill="none" stroke="#000" x1="6" x2="12" y1="12.5" y2="12.5"/><line fill="none" stroke="#000" x1="6" x2="14" y1="8.5" y2="8.5"/><line fill="none" stroke="#000" x1="6" x2="14" y1="6.5" y2="6.5"/><line fill="none" stroke="#000" x1="6" x2="14" y1="10.5" y2="10.5"/></svg>',
            file: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect fill="none" stroke="#000" x="3.5" y="1.5" width="13" height="17"/></svg>',
            flickr: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle cx="5.5" cy="9.5" r="3.5"/><circle cx="14.5" cy="9.5" r="3.5"/></svg>',
            folder: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon fill="none" stroke="#000" points="9.5 5.5 8.5 3.5 1.5 3.5 1.5 16.5 18.5 16.5 18.5 5.5"/></svg>',
            forward: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M2.47,13.11 C4.02,10.02 6.27,7.85 9.04,6.61 C9.48,6.41 10.27,6.13 11,5.91 L11,2 L18.89,9 L11,16 L11,12.13 C9.25,12.47 7.58,13.19 6.02,14.25 C3.03,16.28 1.63,18.54 1.63,18.54 C1.63,18.54 1.38,15.28 2.47,13.11 L2.47,13.11 Z M5.3,13.53 C6.92,12.4 9.04,11.4 12,10.92 L12,13.63 L17.36,9 L12,4.25 L12,6.8 C11.71,6.86 10.86,7.02 9.67,7.49 C6.79,8.65 4.58,10.96 3.49,13.08 C3.18,13.7 2.68,14.87 2.49,16 C3.28,15.05 4.4,14.15 5.3,13.53 L5.3,13.53 Z"/></svg>',
            foursquare: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M15.23,2 C15.96,2 16.4,2.41 16.5,2.86 C16.57,3.15 16.56,3.44 16.51,3.73 C16.46,4.04 14.86,11.72 14.75,12.03 C14.56,12.56 14.16,12.82 13.61,12.83 C13.03,12.84 11.09,12.51 10.69,13 C10.38,13.38 7.79,16.39 6.81,17.53 C6.61,17.76 6.4,17.96 6.08,17.99 C5.68,18.04 5.29,17.87 5.17,17.45 C5.12,17.28 5.1,17.09 5.1,16.91 C5.1,12.4 4.86,7.81 5.11,3.31 C5.17,2.5 5.81,2.12 6.53,2 L15.23,2 L15.23,2 Z M9.76,11.42 C9.94,11.19 10.17,11.1 10.45,11.1 L12.86,11.1 C13.12,11.1 13.31,10.94 13.36,10.69 C13.37,10.64 13.62,9.41 13.74,8.83 C13.81,8.52 13.53,8.28 13.27,8.28 C12.35,8.29 11.42,8.28 10.5,8.28 C9.84,8.28 9.83,7.69 9.82,7.21 C9.8,6.85 10.13,6.55 10.5,6.55 C11.59,6.56 12.67,6.55 13.76,6.55 C14.03,6.55 14.23,6.4 14.28,6.14 C14.34,5.87 14.67,4.29 14.67,4.29 C14.67,4.29 14.82,3.74 14.19,3.74 L7.34,3.74 C7,3.75 6.84,4.02 6.84,4.33 C6.84,7.58 6.85,14.95 6.85,14.99 C6.87,15 8.89,12.51 9.76,11.42 L9.76,11.42 Z"/></svg>',
            future: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline points="19 2 18 2 18 6 14 6 14 7 19 7 19 2"/><path fill="none" stroke="#000" stroke-width="1.1" d="M18,6.548 C16.709,3.29 13.354,1 9.6,1 C4.6,1 0.6,5 0.6,10 C0.6,15 4.6,19 9.6,19 C14.6,19 18.6,15 18.6,10"/><rect x="9" y="4" width="1" height="7"/><path d="M13.018,14.197 L9.445,10.625" fill="none" stroke="#000" stroke-width="1.1"/></svg>',
            "git-branch": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.2" cx="7" cy="3" r="2"/><circle fill="none" stroke="#000" stroke-width="1.2" cx="14" cy="6" r="2"/><circle fill="none" stroke="#000" stroke-width="1.2" cx="7" cy="17" r="2"/><path fill="none" stroke="#000" stroke-width="2" d="M14,8 C14,10.41 12.43,10.87 10.56,11.25 C9.09,11.54 7,12.06 7,15 L7,5"/></svg>',
            "git-fork": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.2" cx="5.79" cy="2.79" r="1.79"/><circle fill="none" stroke="#000" stroke-width="1.2" cx="14.19" cy="2.79" r="1.79"/><ellipse fill="none" stroke="#000" stroke-width="1.2" cx="10.03" cy="16.79" rx="1.79" ry="1.79"/><path fill="none" stroke="#000" stroke-width="2" d="M5.79,4.57 L5.79,6.56 C5.79,9.19 10.03,10.22 10.03,13.31 C10.03,14.86 10.04,14.55 10.04,14.55 C10.04,14.37 10.04,14.86 10.04,13.31 C10.04,10.22 14.2,9.19 14.2,6.56 L14.2,4.57"/></svg>',
            "github-alt": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M10,0.5 C4.75,0.5 0.5,4.76 0.5,10.01 C0.5,15.26 4.75,19.51 10,19.51 C15.24,19.51 19.5,15.26 19.5,10.01 C19.5,4.76 15.25,0.5 10,0.5 L10,0.5 Z M12.81,17.69 C12.81,17.69 12.81,17.7 12.79,17.69 C12.47,17.75 12.35,17.59 12.35,17.36 L12.35,16.17 C12.35,15.45 12.09,14.92 11.58,14.56 C12.2,14.51 12.77,14.39 13.26,14.21 C13.87,13.98 14.36,13.69 14.74,13.29 C15.42,12.59 15.76,11.55 15.76,10.17 C15.76,9.25 15.45,8.46 14.83,7.8 C15.1,7.08 15.07,6.29 14.75,5.44 L14.51,5.42 C14.34,5.4 14.06,5.46 13.67,5.61 C13.25,5.78 12.79,6.03 12.31,6.35 C11.55,6.16 10.81,6.05 10.09,6.05 C9.36,6.05 8.61,6.15 7.88,6.35 C7.28,5.96 6.75,5.68 6.26,5.54 C6.07,5.47 5.9,5.44 5.78,5.44 L5.42,5.44 C5.06,6.29 5.04,7.08 5.32,7.8 C4.7,8.46 4.4,9.25 4.4,10.17 C4.4,11.94 4.96,13.16 6.08,13.84 C6.53,14.13 7.05,14.32 7.69,14.43 C8.03,14.5 8.32,14.54 8.55,14.55 C8.07,14.89 7.82,15.42 7.82,16.16 L7.82,17.51 C7.8,17.69 7.7,17.8 7.51,17.8 C4.21,16.74 1.82,13.65 1.82,10.01 C1.82,5.5 5.49,1.83 10,1.83 C14.5,1.83 18.17,5.5 18.17,10.01 C18.18,13.53 15.94,16.54 12.81,17.69 L12.81,17.69 Z"/></svg>',
            github: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M10,1 C5.03,1 1,5.03 1,10 C1,13.98 3.58,17.35 7.16,18.54 C7.61,18.62 7.77,18.34 7.77,18.11 C7.77,17.9 7.76,17.33 7.76,16.58 C5.26,17.12 4.73,15.37 4.73,15.37 C4.32,14.33 3.73,14.05 3.73,14.05 C2.91,13.5 3.79,13.5 3.79,13.5 C4.69,13.56 5.17,14.43 5.17,14.43 C5.97,15.8 7.28,15.41 7.79,15.18 C7.87,14.6 8.1,14.2 8.36,13.98 C6.36,13.75 4.26,12.98 4.26,9.53 C4.26,8.55 4.61,7.74 5.19,7.11 C5.1,6.88 4.79,5.97 5.28,4.73 C5.28,4.73 6.04,4.49 7.75,5.65 C8.47,5.45 9.24,5.35 10,5.35 C10.76,5.35 11.53,5.45 12.25,5.65 C13.97,4.48 14.72,4.73 14.72,4.73 C15.21,5.97 14.9,6.88 14.81,7.11 C15.39,7.74 15.73,8.54 15.73,9.53 C15.73,12.99 13.63,13.75 11.62,13.97 C11.94,14.25 12.23,14.8 12.23,15.64 C12.23,16.84 12.22,17.81 12.22,18.11 C12.22,18.35 12.38,18.63 12.84,18.54 C16.42,17.35 19,13.98 19,10 C19,5.03 14.97,1 10,1 L10,1 Z"/></svg>',
            gitter: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect x="3.5" y="1" width="1.531" height="11.471"/><rect x="7.324" y="4.059" width="1.529" height="15.294"/><rect x="11.148" y="4.059" width="1.527" height="15.294"/><rect x="14.971" y="4.059" width="1.529" height="8.412"/></svg>',
            "google-plus": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M12.9,9c0,2.7-0.6,5-3.2,6.3c-3.7,1.8-8.1,0.2-9.4-3.6C-1.1,7.6,1.9,3.3,6.1,3c1.7-0.1,3.2,0.3,4.6,1.3 c0.1,0.1,0.3,0.2,0.4,0.4c-0.5,0.5-1.2,1-1.7,1.6c-1-0.8-2.1-1.1-3.5-0.9C5,5.6,4.2,6,3.6,6.7c-1.3,1.3-1.5,3.4-0.5,5 c1,1.7,2.6,2.3,4.6,1.9c1.4-0.3,2.4-1.2,2.6-2.6H6.9V9H12.9z"/><polygon points="20,9 20,11 18,11 18,13 16,13 16,11 14,11 14,9 16,9 16,7 18,7 18,9"/></svg>',
            google: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M17.86,9.09 C18.46,12.12 17.14,16.05 13.81,17.56 C9.45,19.53 4.13,17.68 2.47,12.87 C0.68,7.68 4.22,2.42 9.5,2.03 C11.57,1.88 13.42,2.37 15.05,3.65 C15.22,3.78 15.37,3.93 15.61,4.14 C14.9,4.81 14.23,5.45 13.5,6.14 C12.27,5.08 10.84,4.72 9.28,4.98 C8.12,5.17 7.16,5.76 6.37,6.63 C4.88,8.27 4.62,10.86 5.76,12.82 C6.95,14.87 9.17,15.8 11.57,15.25 C13.27,14.87 14.76,13.33 14.89,11.75 L10.51,11.75 L10.51,9.09 L17.86,9.09 L17.86,9.09 Z"/></svg>',
            grid: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect x="2" y="2" width="3" height="3"/><rect x="8" y="2" width="3" height="3"/><rect x="14" y="2" width="3" height="3"/><rect x="2" y="8" width="3" height="3"/><rect x="8" y="8" width="3" height="3"/><rect x="14" y="8" width="3" height="3"/><rect x="2" y="14" width="3" height="3"/><rect x="8" y="14" width="3" height="3"/><rect x="14" y="14" width="3" height="3"/></svg>',
            happy: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle cx="13" cy="7" r="1"/><circle cx="7" cy="7" r="1"/><circle fill="none" stroke="#000" cx="10" cy="10" r="8.5"/><path fill="none" stroke="#000" d="M14.6,11.4 C13.9,13.3 12.1,14.5 10,14.5 C7.9,14.5 6.1,13.3 5.4,11.4"/></svg>',
            hashtag: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M15.431,8 L15.661,7 L12.911,7 L13.831,3 L12.901,3 L11.98,7 L9.29,7 L10.21,3 L9.281,3 L8.361,7 L5.23,7 L5,8 L8.13,8 L7.21,12 L4.23,12 L4,13 L6.98,13 L6.061,17 L6.991,17 L7.911,13 L10.601,13 L9.681,17 L10.611,17 L11.531,13 L14.431,13 L14.661,12 L11.76,12 L12.681,8 L15.431,8 Z M10.831,12 L8.141,12 L9.061,8 L11.75,8 L10.831,12 Z"/></svg>',
            heart: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" stroke-width="1.03" d="M10,4 C10,4 8.1,2 5.74,2 C3.38,2 1,3.55 1,6.73 C1,8.84 2.67,10.44 2.67,10.44 L10,18 L17.33,10.44 C17.33,10.44 19,8.84 19,6.73 C19,3.55 16.62,2 14.26,2 C11.9,2 10,4 10,4 L10,4 Z"/></svg>',
            history: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="#000" points="1 2 2 2 2 6 6 6 6 7 1 7 1 2"/><path fill="none" stroke="#000" stroke-width="1.1" d="M2.1,6.548 C3.391,3.29 6.746,1 10.5,1 C15.5,1 19.5,5 19.5,10 C19.5,15 15.5,19 10.5,19 C5.5,19 1.5,15 1.5,10"/><rect x="9" y="4" width="1" height="7"/><path fill="none" stroke="#000" stroke-width="1.1" d="M13.018,14.197 L9.445,10.625"/></svg>',
            home: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="18.65 11.35 10 2.71 1.35 11.35 0.65 10.65 10 1.29 19.35 10.65"/><polygon points="15 4 18 4 18 7 17 7 17 5 15 5"/><polygon points="3 11 4 11 4 18 7 18 7 12 12 12 12 18 16 18 16 11 17 11 17 19 11 19 11 13 8 13 8 19 3 19"/></svg>',
            image: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle cx="16.1" cy="6.1" r="1.1"/><rect fill="none" stroke="#000" x=".5" y="2.5" width="19" height="15"/><polyline fill="none" stroke="#000" stroke-width="1.01" points="4,13 8,9 13,14"/><polyline fill="none" stroke="#000" stroke-width="1.01" points="11,12 12.5,10.5 16,14"/></svg>',
            info: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M12.13,11.59 C11.97,12.84 10.35,14.12 9.1,14.16 C6.17,14.2 9.89,9.46 8.74,8.37 C9.3,8.16 10.62,7.83 10.62,8.81 C10.62,9.63 10.12,10.55 9.88,11.32 C8.66,15.16 12.13,11.15 12.14,11.18 C12.16,11.21 12.16,11.35 12.13,11.59 C12.08,11.95 12.16,11.35 12.13,11.59 L12.13,11.59 Z M11.56,5.67 C11.56,6.67 9.36,7.15 9.36,6.03 C9.36,5 11.56,4.54 11.56,5.67 L11.56,5.67 Z"/><circle fill="none" stroke="#000" stroke-width="1.1" cx="10" cy="10" r="9"/></svg>',
            instagram: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M13.55,1H6.46C3.45,1,1,3.44,1,6.44v7.12c0,3,2.45,5.44,5.46,5.44h7.08c3.02,0,5.46-2.44,5.46-5.44V6.44 C19.01,3.44,16.56,1,13.55,1z M17.5,14c0,1.93-1.57,3.5-3.5,3.5H6c-1.93,0-3.5-1.57-3.5-3.5V6c0-1.93,1.57-3.5,3.5-3.5h8 c1.93,0,3.5,1.57,3.5,3.5V14z"/><circle cx="14.87" cy="5.26" r="1.09"/><path d="M10.03,5.45c-2.55,0-4.63,2.06-4.63,4.6c0,2.55,2.07,4.61,4.63,4.61c2.56,0,4.63-2.061,4.63-4.61 C14.65,7.51,12.58,5.45,10.03,5.45L10.03,5.45L10.03,5.45z M10.08,13c-1.66,0-3-1.34-3-2.99c0-1.65,1.34-2.99,3-2.99s3,1.34,3,2.99 C13.08,11.66,11.74,13,10.08,13L10.08,13L10.08,13z"/></svg>',
            italic: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M12.63,5.48 L10.15,14.52 C10,15.08 10.37,15.25 11.92,15.3 L11.72,16 L6,16 L6.2,15.31 C7.78,15.26 8.19,15.09 8.34,14.53 L10.82,5.49 C10.97,4.92 10.63,4.76 9.09,4.71 L9.28,4 L15,4 L14.81,4.69 C13.23,4.75 12.78,4.91 12.63,5.48 L12.63,5.48 Z"/></svg>',
            joomla: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M7.8,13.4l1.7-1.7L5.9,8c-0.6-0.5-0.6-1.5,0-2c0.6-0.6,1.4-0.6,2,0l1.7-1.7c-1-1-2.3-1.3-3.6-1C5.8,2.2,4.8,1.4,3.7,1.4 c-1.3,0-2.3,1-2.3,2.3c0,1.1,0.8,2,1.8,2.3c-0.4,1.3-0.1,2.8,1,3.8L7.8,13.4L7.8,13.4z"/><path d="M10.2,4.3c1-1,2.5-1.4,3.8-1c0.2-1.1,1.1-2,2.3-2c1.3,0,2.3,1,2.3,2.3c0,1.2-0.9,2.2-2,2.3c0.4,1.3,0,2.8-1,3.8L13.9,8 c0.6-0.5,0.6-1.5,0-2c-0.5-0.6-1.5-0.6-2,0L8.2,9.7L6.5,8"/><path d="M14.1,16.8c-1.3,0.4-2.8,0.1-3.8-1l1.7-1.7c0.6,0.6,1.5,0.6,2,0c0.5-0.6,0.6-1.5,0-2l-3.7-3.7L12,6.7l3.7,3.7 c1,1,1.3,2.4,1,3.6c1.1,0.2,2,1.1,2,2.3c0,1.3-1,2.3-2.3,2.3C15.2,18.6,14.3,17.8,14.1,16.8"/><path d="M13.2,12.2l-3.7,3.7c-1,1-2.4,1.3-3.6,1c-0.2,1-1.2,1.8-2.2,1.8c-1.3,0-2.3-1-2.3-2.3c0-1.1,0.8-2,1.8-2.3 c-0.3-1.3,0-2.7,1-3.7l1.7,1.7c-0.6,0.6-0.6,1.5,0,2c0.6,0.6,1.4,0.6,2,0l3.7-3.7"/></svg>',
            laptop: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect y="16" width="20" height="1"/><rect fill="none" stroke="#000" x="2.5" y="4.5" width="15" height="10"/></svg>',
            lifesaver: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M10,0.5 C4.76,0.5 0.5,4.76 0.5,10 C0.5,15.24 4.76,19.5 10,19.5 C15.24,19.5 19.5,15.24 19.5,10 C19.5,4.76 15.24,0.5 10,0.5 L10,0.5 Z M10,1.5 C11.49,1.5 12.89,1.88 14.11,2.56 L11.85,4.82 C11.27,4.61 10.65,4.5 10,4.5 C9.21,4.5 8.47,4.67 7.79,4.96 L5.58,2.75 C6.87,1.95 8.38,1.5 10,1.5 L10,1.5 Z M4.96,7.8 C4.67,8.48 4.5,9.21 4.5,10 C4.5,10.65 4.61,11.27 4.83,11.85 L2.56,14.11 C1.88,12.89 1.5,11.49 1.5,10 C1.5,8.38 1.95,6.87 2.75,5.58 L4.96,7.79 L4.96,7.8 L4.96,7.8 Z M10,18.5 C8.25,18.5 6.62,17.97 5.27,17.06 L7.46,14.87 C8.22,15.27 9.08,15.5 10,15.5 C10.79,15.5 11.53,15.33 12.21,15.04 L14.42,17.25 C13.13,18.05 11.62,18.5 10,18.5 L10,18.5 Z M10,14.5 C7.52,14.5 5.5,12.48 5.5,10 C5.5,7.52 7.52,5.5 10,5.5 C12.48,5.5 14.5,7.52 14.5,10 C14.5,12.48 12.48,14.5 10,14.5 L10,14.5 Z M15.04,12.21 C15.33,11.53 15.5,10.79 15.5,10 C15.5,9.08 15.27,8.22 14.87,7.46 L17.06,5.27 C17.97,6.62 18.5,8.25 18.5,10 C18.5,11.62 18.05,13.13 17.25,14.42 L15.04,12.21 L15.04,12.21 Z"/></svg>',
            link: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" stroke-width="1.1" d="M10.625,12.375 L7.525,15.475 C6.825,16.175 5.925,16.175 5.225,15.475 L4.525,14.775 C3.825,14.074 3.825,13.175 4.525,12.475 L7.625,9.375"/><path fill="none" stroke="#000" stroke-width="1.1" d="M9.325,7.375 L12.425,4.275 C13.125,3.575 14.025,3.575 14.724,4.275 L15.425,4.975 C16.125,5.675 16.125,6.575 15.425,7.275 L12.325,10.375"/><path fill="none" stroke="#000" stroke-width="1.1" d="M7.925,11.875 L11.925,7.975"/></svg>',
            linkedin: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M5.77,17.89 L5.77,7.17 L2.21,7.17 L2.21,17.89 L5.77,17.89 L5.77,17.89 Z M3.99,5.71 C5.23,5.71 6.01,4.89 6.01,3.86 C5.99,2.8 5.24,2 4.02,2 C2.8,2 2,2.8 2,3.85 C2,4.88 2.77,5.7 3.97,5.7 L3.99,5.7 L3.99,5.71 L3.99,5.71 Z"/><path d="M7.75,17.89 L11.31,17.89 L11.31,11.9 C11.31,11.58 11.33,11.26 11.43,11.03 C11.69,10.39 12.27,9.73 13.26,9.73 C14.55,9.73 15.06,10.71 15.06,12.15 L15.06,17.89 L18.62,17.89 L18.62,11.74 C18.62,8.45 16.86,6.92 14.52,6.92 C12.6,6.92 11.75,7.99 11.28,8.73 L11.3,8.73 L11.3,7.17 L7.75,7.17 C7.79,8.17 7.75,17.89 7.75,17.89 L7.75,17.89 L7.75,17.89 Z"/></svg>',
            list: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect x="6" y="4" width="12" height="1"/><rect x="6" y="9" width="12" height="1"/><rect x="6" y="14" width="12" height="1"/><rect x="2" y="4" width="2" height="1"/><rect x="2" y="9" width="2" height="1"/><rect x="2" y="14" width="2" height="1"/></svg>',
            location: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" stroke-width="1.01" d="M10,0.5 C6.41,0.5 3.5,3.39 3.5,6.98 C3.5,11.83 10,19 10,19 C10,19 16.5,11.83 16.5,6.98 C16.5,3.39 13.59,0.5 10,0.5 L10,0.5 Z"/><circle fill="none" stroke="#000" cx="10" cy="6.8" r="2.3"/></svg>',
            lock: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect fill="none" stroke="#000" height="10" width="13" y="8.5" x="3.5"/><path fill="none" stroke="#000" d="M6.5,8 L6.5,4.88 C6.5,3.01 8.07,1.5 10,1.5 C11.93,1.5 13.5,3.01 13.5,4.88 L13.5,8"/></svg>',
            mail: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" points="1.4,6.5 10,11 18.6,6.5"/><path d="M 1,4 1,16 19,16 19,4 1,4 Z M 18,15 2,15 2,5 18,5 18,15 Z"/></svg>',
            menu: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect x="2" y="4" width="16" height="1"/><rect x="2" y="9" width="16" height="1"/><rect x="2" y="14" width="16" height="1"/></svg>',
            microphone: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><line fill="none" stroke="#000" x1="10" x2="10" y1="16.44" y2="18.5"/><line fill="none" stroke="#000" x1="7" x2="13" y1="18.5" y2="18.5"/><path fill="none" stroke="#000" stroke-width="1.1" d="M13.5 4.89v5.87a3.5 3.5 0 0 1-7 0V4.89a3.5 3.5 0 0 1 7 0z"/><path fill="none" stroke="#000" stroke-width="1.1" d="M15.5 10.36V11a5.5 5.5 0 0 1-11 0v-.6"/></svg>',
            "minus-circle": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.1" cx="9.5" cy="9.5" r="9"/><line fill="none" stroke="#000" x1="5" y1="9.5" x2="14" y2="9.5"/></svg>',
            minus: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect height="1" width="18" y="9" x="1"/></svg>',
            "more-vertical": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle cx="10" cy="3" r="2"/><circle cx="10" cy="10" r="2"/><circle cx="10" cy="17" r="2"/></svg>',
            more: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle cx="3" cy="10" r="2"/><circle cx="10" cy="10" r="2"/><circle cx="17" cy="10" r="2"/></svg>',
            move: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="4,5 1,5 1,9 2,9 2,6 4,6"/><polygon points="1,16 2,16 2,18 4,18 4,19 1,19"/><polygon points="14,16 14,19 11,19 11,18 13,18 13,16"/><rect fill="none" stroke="#000" x="5.5" y="1.5" width="13" height="13"/><rect x="1" y="11" width="1" height="3"/><rect x="6" y="18" width="3" height="1"/></svg>',
            nut: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon fill="none" stroke="#000" points="2.5,5.7 10,1.3 17.5,5.7 17.5,14.3 10,18.7 2.5,14.3"/><circle fill="none" stroke="#000" cx="10" cy="10" r="3.5"/></svg>',
            pagekit: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="3,1 17,1 17,16 10,16 10,13 14,13 14,4 6,4 6,16 10,16 10,19 3,19"/></svg>',
            "paint-bucket": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M10.21,1 L0,11.21 L8.1,19.31 L18.31,9.1 L10.21,1 L10.21,1 Z M16.89,9.1 L15,11 L1.7,11 L10.21,2.42 L16.89,9.1 Z"/><path fill="none" stroke="#000" stroke-width="1.1" d="M6.42,2.33 L11.7,7.61"/><path d="M18.49,12 C18.49,12 20,14.06 20,15.36 C20,16.28 19.24,17 18.49,17 L18.49,17 C17.74,17 17,16.28 17,15.36 C17,14.06 18.49,12 18.49,12 L18.49,12 Z"/></svg>',
            pencil: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" d="M17.25,6.01 L7.12,16.1 L3.82,17.2 L5.02,13.9 L15.12,3.88 C15.71,3.29 16.66,3.29 17.25,3.88 C17.83,4.47 17.83,5.42 17.25,6.01 L17.25,6.01 Z"/><path fill="none" stroke="#000" d="M15.98,7.268 L13.851,5.148"/></svg>',
            "phone-landscape": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" d="M17,5.5 C17.8,5.5 18.5,6.2 18.5,7 L18.5,14 C18.5,14.8 17.8,15.5 17,15.5 L3,15.5 C2.2,15.5 1.5,14.8 1.5,14 L1.5,7 C1.5,6.2 2.2,5.5 3,5.5 L17,5.5 L17,5.5 L17,5.5 Z"/><circle cx="3.8" cy="10.5" r=".8"/></svg>',
            phone: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" d="M15.5,17 C15.5,17.8 14.8,18.5 14,18.5 L7,18.5 C6.2,18.5 5.5,17.8 5.5,17 L5.5,3 C5.5,2.2 6.2,1.5 7,1.5 L14,1.5 C14.8,1.5 15.5,2.2 15.5,3 L15.5,17 L15.5,17 L15.5,17 Z"/><circle cx="10.5" cy="16.5" r=".8"/></svg>',
            pinterest: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M10.21,1 C5.5,1 3,4.16 3,7.61 C3,9.21 3.85,11.2 5.22,11.84 C5.43,11.94 5.54,11.89 5.58,11.69 C5.62,11.54 5.8,10.8 5.88,10.45 C5.91,10.34 5.89,10.24 5.8,10.14 C5.36,9.59 5,8.58 5,7.65 C5,5.24 6.82,2.91 9.93,2.91 C12.61,2.91 14.49,4.74 14.49,7.35 C14.49,10.3 13,12.35 11.06,12.35 C9.99,12.35 9.19,11.47 9.44,10.38 C9.75,9.08 10.35,7.68 10.35,6.75 C10.35,5.91 9.9,5.21 8.97,5.21 C7.87,5.21 6.99,6.34 6.99,7.86 C6.99,8.83 7.32,9.48 7.32,9.48 C7.32,9.48 6.24,14.06 6.04,14.91 C5.7,16.35 6.08,18.7 6.12,18.9 C6.14,19.01 6.26,19.05 6.33,18.95 C6.44,18.81 7.74,16.85 8.11,15.44 C8.24,14.93 8.79,12.84 8.79,12.84 C9.15,13.52 10.19,14.09 11.29,14.09 C14.58,14.09 16.96,11.06 16.96,7.3 C16.94,3.7 14,1 10.21,1"/></svg>',
            "play-circle": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon fill="none" stroke="#000" stroke-width="1.1" points="8.5 7 13.5 10 8.5 13"/><circle fill="none" stroke="#000" stroke-width="1.1" cx="10" cy="10" r="9"/></svg>',
            play: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon fill="none" stroke="#000" points="6.5,5 14.5,10 6.5,15"/></svg>',
            "plus-circle": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.1" cx="9.5" cy="9.5" r="9"/><line fill="none" stroke="#000" x1="9.5" y1="5" x2="9.5" y2="14"/><line fill="none" stroke="#000" x1="5" y1="9.5" x2="14" y2="9.5"/></svg>',
            plus: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect x="9" y="1" width="1" height="17"/><rect x="1" y="9" width="17" height="1"/></svg>',
            print: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" points="4.5 13.5 1.5 13.5 1.5 6.5 18.5 6.5 18.5 13.5 15.5 13.5"/><polyline fill="none" stroke="#000" points="15.5 6.5 15.5 2.5 4.5 2.5 4.5 6.5"/><rect fill="none" stroke="#000" width="11" height="6" x="4.5" y="11.5"/><rect width="8" height="1" x="6" y="13"/><rect width="8" height="1" x="6" y="15"/></svg>',
            pull: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="6.85,8 9.5,10.6 12.15,8 12.85,8.7 9.5,12 6.15,8.7"/><line fill="none" stroke="#000" x1="9.5" y1="11" x2="9.5" y2="2"/><polyline fill="none" stroke="#000" points="6,5.5 3.5,5.5 3.5,18.5 15.5,18.5 15.5,5.5 13,5.5"/></svg>',
            push: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="12.15,4 9.5,1.4 6.85,4 6.15,3.3 9.5,0 12.85,3.3"/><line fill="none" stroke="#000" x1="9.5" y1="10" x2="9.5" y2="1"/><polyline fill="none" stroke="#000" points="6 5.5 3.5 5.5 3.5 18.5 15.5 18.5 15.5 5.5 13 5.5"/></svg>',
            question: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.1" cx="10" cy="10" r="9"/><circle cx="10.44" cy="14.42" r="1.05"/><path fill="none" stroke="#000" stroke-width="1.2" d="M8.17,7.79 C8.17,4.75 12.72,4.73 12.72,7.72 C12.72,8.67 11.81,9.15 11.23,9.75 C10.75,10.24 10.51,10.73 10.45,11.4 C10.44,11.53 10.43,11.64 10.43,11.75"/></svg>',
            "quote-right": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M17.27,7.79 C17.27,9.45 16.97,10.43 15.99,12.02 C14.98,13.64 13,15.23 11.56,15.97 L11.1,15.08 C12.34,14.2 13.14,13.51 14.02,11.82 C14.27,11.34 14.41,10.92 14.49,10.54 C14.3,10.58 14.09,10.6 13.88,10.6 C12.06,10.6 10.59,9.12 10.59,7.3 C10.59,5.48 12.06,4 13.88,4 C15.39,4 16.67,5.02 17.05,6.42 C17.19,6.82 17.27,7.27 17.27,7.79 L17.27,7.79 Z"/><path d="M8.68,7.79 C8.68,9.45 8.38,10.43 7.4,12.02 C6.39,13.64 4.41,15.23 2.97,15.97 L2.51,15.08 C3.75,14.2 4.55,13.51 5.43,11.82 C5.68,11.34 5.82,10.92 5.9,10.54 C5.71,10.58 5.5,10.6 5.29,10.6 C3.47,10.6 2,9.12 2,7.3 C2,5.48 3.47,4 5.29,4 C6.8,4 8.08,5.02 8.46,6.42 C8.6,6.82 8.68,7.27 8.68,7.79 L8.68,7.79 Z"/></svg>',
            receiver: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" stroke-width="1.01" d="M6.189,13.611C8.134,15.525 11.097,18.239 13.867,18.257C16.47,18.275 18.2,16.241 18.2,16.241L14.509,12.551L11.539,13.639L6.189,8.29L7.313,5.355L3.76,1.8C3.76,1.8 1.732,3.537 1.7,6.092C1.667,8.809 4.347,11.738 6.189,13.611"/></svg>',
            reddit: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M19 9.05a2.56 2.56 0 0 0-2.56-2.56 2.59 2.59 0 0 0-1.88.82 10.63 10.63 0 0 0-4.14-1v-.08c.58-1.62 1.58-3.89 2.7-4.1.38-.08.77.12 1.19.57a1.15 1.15 0 0 0-.06.37 1.48 1.48 0 1 0 1.51-1.45 1.43 1.43 0 0 0-.76.19A2.29 2.29 0 0 0 12.91 1c-2.11.43-3.39 4.38-3.63 5.19 0 0 0 .11-.06.11a10.65 10.65 0 0 0-3.75 1A2.56 2.56 0 0 0 1 9.05a2.42 2.42 0 0 0 .72 1.76A5.18 5.18 0 0 0 1.24 13c0 3.66 3.92 6.64 8.73 6.64s8.74-3 8.74-6.64a5.23 5.23 0 0 0-.46-2.13A2.58 2.58 0 0 0 19 9.05zm-16.88 0a1.44 1.44 0 0 1 2.27-1.19 7.68 7.68 0 0 0-2.07 1.91 1.33 1.33 0 0 1-.2-.72zM10 18.4c-4.17 0-7.55-2.4-7.55-5.4S5.83 7.53 10 7.53 17.5 10 17.5 13s-3.38 5.4-7.5 5.4zm7.69-8.61a7.62 7.62 0 0 0-2.09-1.91 1.41 1.41 0 0 1 .84-.28 1.47 1.47 0 0 1 1.44 1.45 1.34 1.34 0 0 1-.21.72z"/><path d="M6.69 12.58a1.39 1.39 0 1 1 1.39-1.39 1.38 1.38 0 0 1-1.38 1.39z"/><path d="M14.26 11.2a1.39 1.39 0 1 1-1.39-1.39 1.39 1.39 0 0 1 1.39 1.39z"/><path d="M13.09 14.88a.54.54 0 0 1-.09.77 5.3 5.3 0 0 1-3.26 1.19 5.61 5.61 0 0 1-3.4-1.22.55.55 0 1 1 .73-.83 4.09 4.09 0 0 0 5.25 0 .56.56 0 0 1 .77.09z"/></svg>',
            refresh: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" stroke-width="1.1" d="M17.08,11.15 C17.09,11.31 17.1,11.47 17.1,11.64 C17.1,15.53 13.94,18.69 10.05,18.69 C6.16,18.68 3,15.53 3,11.63 C3,7.74 6.16,4.58 10.05,4.58 C10.9,4.58 11.71,4.73 12.46,5"/><polyline fill="none" stroke="#000" points="9.9 2 12.79 4.89 9.79 7.9"/></svg>',
            reply: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M17.7,13.11 C16.12,10.02 13.84,7.85 11.02,6.61 C10.57,6.41 9.75,6.13 9,5.91 L9,2 L1,9 L9,16 L9,12.13 C10.78,12.47 12.5,13.19 14.09,14.25 C17.13,16.28 18.56,18.54 18.56,18.54 C18.56,18.54 18.81,15.28 17.7,13.11 L17.7,13.11 Z M14.82,13.53 C13.17,12.4 11.01,11.4 8,10.92 L8,13.63 L2.55,9 L8,4.25 L8,6.8 C8.3,6.86 9.16,7.02 10.37,7.49 C13.3,8.65 15.54,10.96 16.65,13.08 C16.97,13.7 17.48,14.86 17.68,16 C16.87,15.05 15.73,14.15 14.82,13.53 L14.82,13.53 Z"/></svg>',
            rss: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle cx="3.12" cy="16.8" r="1.85"/><path fill="none" stroke="#000" stroke-width="1.1" d="M1.5,8.2 C1.78,8.18 2.06,8.16 2.35,8.16 C7.57,8.16 11.81,12.37 11.81,17.57 C11.81,17.89 11.79,18.19 11.76,18.5"/><path fill="none" stroke="#000" stroke-width="1.1" d="M1.5,2.52 C1.78,2.51 2.06,2.5 2.35,2.5 C10.72,2.5 17.5,9.24 17.5,17.57 C17.5,17.89 17.49,18.19 17.47,18.5"/></svg>',
            search: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.1" cx="9" cy="9" r="7"/><path fill="none" stroke="#000" stroke-width="1.1" d="M14,14 L18,18 L14,14 Z"/></svg>',
            server: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect x="3" y="3" width="1" height="2"/><rect x="5" y="3" width="1" height="2"/><rect x="7" y="3" width="1" height="2"/><rect x="16" y="3" width="1" height="1"/><rect x="16" y="10" width="1" height="1"/><circle fill="none" stroke="#000" cx="9.9" cy="17.4" r="1.4"/><rect x="3" y="10" width="1" height="2"/><rect x="5" y="10" width="1" height="2"/><rect x="9.5" y="14" width="1" height="2"/><rect x="3" y="17" width="6" height="1"/><rect x="11" y="17" width="6" height="1"/><rect fill="none" stroke="#000" x="1.5" y="1.5" width="17" height="5"/><rect fill="none" stroke="#000" x="1.5" y="8.5" width="17" height="5"/></svg>',
            settings: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><ellipse fill="none" stroke="#000" cx="6.11" cy="3.55" rx="2.11" ry="2.15"/><ellipse fill="none" stroke="#000" cx="6.11" cy="15.55" rx="2.11" ry="2.15"/><circle fill="none" stroke="#000" cx="13.15" cy="9.55" r="2.15"/><rect x="1" y="3" width="3" height="1"/><rect x="10" y="3" width="8" height="1"/><rect x="1" y="9" width="8" height="1"/><rect x="15" y="9" width="3" height="1"/><rect x="1" y="15" width="3" height="1"/><rect x="10" y="15" width="8" height="1"/></svg>',
            shrink: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="11 4 12 4 12 8 16 8 16 9 11 9"/><polygon points="4 11 9 11 9 16 8 16 8 12 4 12"/><path fill="none" stroke="#000" stroke-width="1.1" d="M12,8 L18,2"/><path fill="none" stroke="#000" stroke-width="1.1" d="M2,18 L8,12"/></svg>',
            "sign-in": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="7 2 17 2 17 17 7 17 7 16 16 16 16 3 7 3"/><polygon points="9.1 13.4 8.5 12.8 11.28 10 4 10 4 9 11.28 9 8.5 6.2 9.1 5.62 13 9.5"/></svg>',
            "sign-out": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="13.1 13.4 12.5 12.8 15.28 10 8 10 8 9 15.28 9 12.5 6.2 13.1 5.62 17 9.5"/><polygon points="13 2 3 2 3 17 13 17 13 16 4 16 4 3 13 3"/></svg>',
            social: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><line fill="none" stroke="#000" stroke-width="1.1" x1="13.4" y1="14" x2="6.3" y2="10.7"/><line fill="none" stroke="#000" stroke-width="1.1" x1="13.5" y1="5.5" x2="6.5" y2="8.8"/><circle fill="none" stroke="#000" stroke-width="1.1" cx="15.5" cy="4.6" r="2.3"/><circle fill="none" stroke="#000" stroke-width="1.1" cx="15.5" cy="14.8" r="2.3"/><circle fill="none" stroke="#000" stroke-width="1.1" cx="4.5" cy="9.8" r="2.3"/></svg>',
            soundcloud: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M17.2,9.4c-0.4,0-0.8,0.1-1.101,0.2c-0.199-2.5-2.399-4.5-5-4.5c-0.6,0-1.2,0.1-1.7,0.3C9.2,5.5,9.1,5.6,9.1,5.6V15h8 c1.601,0,2.801-1.2,2.801-2.8C20,10.7,18.7,9.4,17.2,9.4L17.2,9.4z"/><rect x="6" y="6.5" width="1.5" height="8.5"/><rect x="3" y="8" width="1.5" height="7"/><rect y="10" width="1.5" height="5"/></svg>',
            star: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon fill="none" stroke="#000" stroke-width="1.01" points="10 2 12.63 7.27 18.5 8.12 14.25 12.22 15.25 18 10 15.27 4.75 18 5.75 12.22 1.5 8.12 7.37 7.27"/></svg>',
            strikethrough: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M6,13.02 L6.65,13.02 C7.64,15.16 8.86,16.12 10.41,16.12 C12.22,16.12 12.92,14.93 12.92,13.89 C12.92,12.55 11.99,12.03 9.74,11.23 C8.05,10.64 6.23,10.11 6.23,7.83 C6.23,5.5 8.09,4.09 10.4,4.09 C11.44,4.09 12.13,4.31 12.72,4.54 L13.33,4 L13.81,4 L13.81,7.59 L13.16,7.59 C12.55,5.88 11.52,4.89 10.07,4.89 C8.84,4.89 7.89,5.69 7.89,7.03 C7.89,8.29 8.89,8.78 10.88,9.45 C12.57,10.03 14.38,10.6 14.38,12.91 C14.38,14.75 13.27,16.93 10.18,16.93 C9.18,16.93 8.17,16.69 7.46,16.39 L6.52,17 L6,17 L6,13.02 L6,13.02 Z"/><rect x="3" y="10" width="15" height="1"/></svg>',
            table: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect x="1" y="3" width="18" height="1"/><rect x="1" y="7" width="18" height="1"/><rect x="1" y="11" width="18" height="1"/><rect x="1" y="15" width="18" height="1"/></svg>',
            "tablet-landscape": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" d="M1.5,5 C1.5,4.2 2.2,3.5 3,3.5 L17,3.5 C17.8,3.5 18.5,4.2 18.5,5 L18.5,16 C18.5,16.8 17.8,17.5 17,17.5 L3,17.5 C2.2,17.5 1.5,16.8 1.5,16 L1.5,5 L1.5,5 L1.5,5 Z"/><circle cx="3.7" cy="10.5" r=".8"/></svg>',
            tablet: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" d="M5,18.5 C4.2,18.5 3.5,17.8 3.5,17 L3.5,3 C3.5,2.2 4.2,1.5 5,1.5 L16,1.5 C16.8,1.5 17.5,2.2 17.5,3 L17.5,17 C17.5,17.8 16.8,18.5 16,18.5 L5,18.5 L5,18.5 L5,18.5 Z"/><circle cx="10.5" cy="16.3" r=".8"/></svg>',
            tag: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" stroke-width="1.1" d="M17.5,3.71 L17.5,7.72 C17.5,7.96 17.4,8.2 17.21,8.39 L8.39,17.2 C7.99,17.6 7.33,17.6 6.93,17.2 L2.8,13.07 C2.4,12.67 2.4,12.01 2.8,11.61 L11.61,2.8 C11.81,2.6 12.08,2.5 12.34,2.5 L16.19,2.5 C16.52,2.5 16.86,2.63 17.11,2.88 C17.35,3.11 17.48,3.4 17.5,3.71 L17.5,3.71 Z"/><circle cx="14" cy="6" r="1"/></svg>',
            thumbnails: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect fill="none" stroke="#000" x="3.5" y="3.5" width="5" height="5"/><rect fill="none" stroke="#000" x="11.5" y="3.5" width="5" height="5"/><rect fill="none" stroke="#000" x="11.5" y="11.5" width="5" height="5"/><rect fill="none" stroke="#000" x="3.5" y="11.5" width="5" height="5"/></svg>',
            trash: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" points="6.5 3 6.5 1.5 13.5 1.5 13.5 3"/><polyline fill="none" stroke="#000" points="4.5 4 4.5 18.5 15.5 18.5 15.5 4"/><rect x="8" y="7" width="1" height="9"/><rect x="11" y="7" width="1" height="9"/><rect x="2" y="3" width="16" height="1"/></svg>',
            "triangle-down": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="5 7 15 7 10 12"/></svg>',
            "triangle-left": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="12 5 7 10 12 15"/></svg>',
            "triangle-right": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="8 5 13 10 8 15"/></svg>',
            "triangle-up": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="5 13 10 8 15 13"/></svg>',
            tripadvisor: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M19.021,7.866C19.256,6.862,20,5.854,20,5.854h-3.346C14.781,4.641,12.504,4,9.98,4C7.363,4,4.999,4.651,3.135,5.876H0\tc0,0,0.738,0.987,0.976,1.988c-0.611,0.837-0.973,1.852-0.973,2.964c0,2.763,2.249,5.009,5.011,5.009\tc1.576,0,2.976-0.737,3.901-1.879l1.063,1.599l1.075-1.615c0.475,0.611,1.1,1.111,1.838,1.451c1.213,0.547,2.574,0.612,3.825,0.15\tc2.589-0.963,3.913-3.852,2.964-6.439c-0.175-0.463-0.4-0.876-0.675-1.238H19.021z M16.38,14.594\tc-1.002,0.371-2.088,0.328-3.06-0.119c-0.688-0.317-1.252-0.817-1.657-1.438c-0.164-0.25-0.313-0.52-0.417-0.811\tc-0.124-0.328-0.186-0.668-0.217-1.014c-0.063-0.689,0.037-1.396,0.339-2.043c0.448-0.971,1.251-1.71,2.25-2.079\tc2.075-0.765,4.375,0.3,5.14,2.366c0.762,2.066-0.301,4.37-2.363,5.134L16.38,14.594L16.38,14.594z M8.322,13.066\tc-0.72,1.059-1.935,1.76-3.309,1.76c-2.207,0-4.001-1.797-4.001-3.996c0-2.203,1.795-4.002,4.001-4.002\tc2.204,0,3.999,1.8,3.999,4.002c0,0.137-0.024,0.261-0.04,0.396c-0.067,0.678-0.284,1.313-0.648,1.853v-0.013H8.322z M2.472,10.775\tc0,1.367,1.112,2.479,2.476,2.479c1.363,0,2.472-1.11,2.472-2.479c0-1.359-1.11-2.468-2.472-2.468\tC3.584,8.306,2.473,9.416,2.472,10.775L2.472,10.775z M12.514,10.775c0,1.367,1.104,2.479,2.471,2.479\tc1.363,0,2.474-1.108,2.474-2.479c0-1.359-1.11-2.468-2.474-2.468c-1.364,0-2.477,1.109-2.477,2.468H12.514z M3.324,10.775\tc0-0.893,0.726-1.618,1.614-1.618c0.889,0,1.625,0.727,1.625,1.618c0,0.898-0.725,1.627-1.625,1.627\tc-0.901,0-1.625-0.729-1.625-1.627H3.324z M13.354,10.775c0-0.893,0.726-1.618,1.627-1.618c0.886,0,1.61,0.727,1.61,1.618\tc0,0.898-0.726,1.627-1.626,1.627s-1.625-0.729-1.625-1.627H13.354z M9.977,4.875c1.798,0,3.425,0.324,4.849,0.968\tc-0.535,0.015-1.061,0.108-1.586,0.3c-1.264,0.463-2.264,1.388-2.815,2.604c-0.262,0.551-0.398,1.133-0.448,1.72\tC9.79,7.905,7.677,5.873,5.076,5.82C6.501,5.208,8.153,4.875,9.94,4.875H9.977z"/></svg>',
            tumblr: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M6.885,8.598c0,0,0,3.393,0,4.996c0,0.282,0,0.66,0.094,0.942c0.377,1.509,1.131,2.545,2.545,3.11 c1.319,0.472,2.356,0.472,3.676,0c0.565-0.188,1.132-0.659,1.132-0.659l-0.849-2.263c0,0-1.036,0.378-1.603,0.283 c-0.565-0.094-1.226-0.66-1.226-1.508c0-1.603,0-4.902,0-4.902h2.828V5.771h-2.828V2H8.205c0,0-0.094,0.66-0.188,0.942 C7.828,3.791,7.262,4.733,6.603,5.394C5.848,6.147,5,6.43,5,6.43v2.168H6.885z"/></svg>',
            tv: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect x="7" y="16" width="6" height="1"/><rect fill="none" stroke="#000" x=".5" y="3.5" width="19" height="11"/></svg>',
            twitter: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M19,4.74 C18.339,5.029 17.626,5.229 16.881,5.32 C17.644,4.86 18.227,4.139 18.503,3.28 C17.79,3.7 17.001,4.009 16.159,4.17 C15.485,3.45 14.526,3 13.464,3 C11.423,3 9.771,4.66 9.771,6.7 C9.771,6.99 9.804,7.269 9.868,7.539 C6.795,7.38 4.076,5.919 2.254,3.679 C1.936,4.219 1.754,4.86 1.754,5.539 C1.754,6.82 2.405,7.95 3.397,8.61 C2.79,8.589 2.22,8.429 1.723,8.149 L1.723,8.189 C1.723,9.978 2.997,11.478 4.686,11.82 C4.376,11.899 4.049,11.939 3.713,11.939 C3.475,11.939 3.245,11.919 3.018,11.88 C3.49,13.349 4.852,14.419 6.469,14.449 C5.205,15.429 3.612,16.019 1.882,16.019 C1.583,16.019 1.29,16.009 1,15.969 C2.635,17.019 4.576,17.629 6.662,17.629 C13.454,17.629 17.17,12 17.17,7.129 C17.17,6.969 17.166,6.809 17.157,6.649 C17.879,6.129 18.504,5.478 19,4.74"/></svg>',
            uikit: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon points="14.4,3.1 11.3,5.1 15,7.3 15,12.9 10,15.7 5,12.9 5,8.5 2,6.8 2,14.8 9.9,19.5 18,14.8 18,5.3"/><polygon points="9.8,4.2 6.7,2.4 9.8,0.4 12.9,2.3"/></svg>',
            unlock: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><rect fill="none" stroke="#000" x="3.5" y="8.5" width="13" height="10"/><path fill="none" stroke="#000" d="M6.5,8.5 L6.5,4.9 C6.5,3 8.1,1.5 10,1.5 C11.9,1.5 13.5,3 13.5,4.9"/></svg>',
            upload: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polyline fill="none" stroke="#000" points="5 8 9.5 3.5 14 8"/><rect x="3" y="17" width="13" height="1"/><line fill="none" stroke="#000" x1="9.5" y1="15" x2="9.5" y2="4"/></svg>',
            user: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.1" cx="9.9" cy="6.4" r="4.4"/><path fill="none" stroke="#000" stroke-width="1.1" d="M1.5,19 C2.3,14.5 5.8,11.2 10,11.2 C14.2,11.2 17.7,14.6 18.5,19.2"/></svg>',
            users: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle fill="none" stroke="#000" stroke-width="1.1" cx="7.7" cy="8.6" r="3.5"/><path fill="none" stroke="#000" stroke-width="1.1" d="M1,18.1 C1.7,14.6 4.4,12.1 7.6,12.1 C10.9,12.1 13.7,14.8 14.3,18.3"/><path fill="none" stroke="#000" stroke-width="1.1" d="M11.4,4 C12.8,2.4 15.4,2.8 16.3,4.7 C17.2,6.6 15.7,8.9 13.6,8.9 C16.5,8.9 18.8,11.3 19.2,14.1"/></svg>',
            "video-camera": '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><polygon fill="none" stroke="#000" points="17.5 6.9 17.5 13.1 13.5 10.4 13.5 14.5 2.5 14.5 2.5 5.5 13.5 5.5 13.5 9.6 17.5 6.9"/></svg>',
            vimeo: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M2.065,7.59C1.84,7.367,1.654,7.082,1.468,6.838c-0.332-0.42-0.137-0.411,0.274-0.772c1.026-0.91,2.004-1.896,3.127-2.688 c1.017-0.713,2.365-1.173,3.286-0.039c0.849,1.045,0.869,2.629,1.084,3.891c0.215,1.309,0.421,2.648,0.88,3.901 c0.127,0.352,0.37,1.018,0.81,1.074c0.567,0.078,1.145-0.917,1.408-1.289c0.684-0.987,1.611-2.317,1.494-3.587 c-0.115-1.349-1.572-1.095-2.482-0.773c0.146-1.514,1.555-3.216,2.912-3.792c1.439-0.597,3.579-0.587,4.302,1.036 c0.772,1.759,0.078,3.802-0.763,5.396c-0.918,1.731-2.1,3.333-3.363,4.829c-1.114,1.329-2.432,2.787-4.093,3.422 c-1.897,0.723-3.021-0.686-3.667-2.318c-0.705-1.777-1.056-3.771-1.565-5.621C4.898,8.726,4.644,7.836,4.136,7.191 C3.473,6.358,2.72,7.141,2.065,7.59C1.977,7.502,2.115,7.551,2.065,7.59L2.065,7.59z"/></svg>',
            warning: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><circle cx="10" cy="14" r="1"/><circle fill="none" stroke="#000" stroke-width="1.1" cx="10" cy="10" r="9"/><path d="M10.97,7.72 C10.85,9.54 10.56,11.29 10.56,11.29 C10.51,11.87 10.27,12 9.99,12 C9.69,12 9.49,11.87 9.43,11.29 C9.43,11.29 9.16,9.54 9.03,7.72 C8.96,6.54 9.03,6 9.03,6 C9.03,5.45 9.46,5.02 9.99,5 C10.53,5.01 10.97,5.44 10.97,6 C10.97,6 11.04,6.54 10.97,7.72 L10.97,7.72 Z"/></svg>',
            whatsapp: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M16.7,3.3c-1.8-1.8-4.1-2.8-6.7-2.8c-5.2,0-9.4,4.2-9.4,9.4c0,1.7,0.4,3.3,1.3,4.7l-1.3,4.9l5-1.3c1.4,0.8,2.9,1.2,4.5,1.2 l0,0l0,0c5.2,0,9.4-4.2,9.4-9.4C19.5,7.4,18.5,5,16.7,3.3 M10.1,17.7L10.1,17.7c-1.4,0-2.8-0.4-4-1.1l-0.3-0.2l-3,0.8l0.8-2.9 l-0.2-0.3c-0.8-1.2-1.2-2.7-1.2-4.2c0-4.3,3.5-7.8,7.8-7.8c2.1,0,4.1,0.8,5.5,2.3c1.5,1.5,2.3,3.4,2.3,5.5 C17.9,14.2,14.4,17.7,10.1,17.7 M14.4,11.9c-0.2-0.1-1.4-0.7-1.6-0.8c-0.2-0.1-0.4-0.1-0.5,0.1c-0.2,0.2-0.6,0.8-0.8,0.9 c-0.1,0.2-0.3,0.2-0.5,0.1c-0.2-0.1-1-0.4-1.9-1.2c-0.7-0.6-1.2-1.4-1.3-1.6c-0.1-0.2,0-0.4,0.1-0.5C8,8.8,8.1,8.7,8.2,8.5 c0.1-0.1,0.2-0.2,0.2-0.4c0.1-0.2,0-0.3,0-0.4C8.4,7.6,7.9,6.5,7.7,6C7.5,5.5,7.3,5.6,7.2,5.6c-0.1,0-0.3,0-0.4,0 c-0.2,0-0.4,0.1-0.6,0.3c-0.2,0.2-0.8,0.8-0.8,2c0,1.2,0.8,2.3,1,2.4c0.1,0.2,1.7,2.5,4,3.5c0.6,0.2,1,0.4,1.3,0.5 c0.6,0.2,1.1,0.2,1.5,0.1c0.5-0.1,1.4-0.6,1.6-1.1c0.2-0.5,0.2-1,0.1-1.1C14.8,12.1,14.6,12,14.4,11.9"/></svg>',
            wordpress: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M10,0.5c-5.2,0-9.5,4.3-9.5,9.5s4.3,9.5,9.5,9.5c5.2,0,9.5-4.3,9.5-9.5S15.2,0.5,10,0.5L10,0.5L10,0.5z M15.6,3.9h-0.1 c-0.8,0-1.4,0.7-1.4,1.5c0,0.7,0.4,1.3,0.8,1.9c0.3,0.6,0.7,1.3,0.7,2.3c0,0.7-0.3,1.5-0.6,2.7L14.1,15l-3-8.9 c0.5,0,0.9-0.1,0.9-0.1C12.5,6,12.5,5.3,12,5.4c0,0-1.3,0.1-2.2,0.1C9,5.5,7.7,5.4,7.7,5.4C7.2,5.3,7.2,6,7.6,6c0,0,0.4,0.1,0.9,0.1 l1.3,3.5L8,15L5,6.1C5.5,6.1,5.9,6,5.9,6C6.4,6,6.3,5.3,5.9,5.4c0,0-1.3,0.1-2.2,0.1c-0.2,0-0.3,0-0.5,0c1.5-2.2,4-3.7,6.9-3.7 C12.2,1.7,14.1,2.6,15.6,3.9L15.6,3.9L15.6,3.9z M2.5,6.6l3.9,10.8c-2.7-1.3-4.6-4.2-4.6-7.4C1.8,8.8,2,7.6,2.5,6.6L2.5,6.6L2.5,6.6 z M10.2,10.7l2.5,6.9c0,0,0,0.1,0.1,0.1C11.9,18,11,18.2,10,18.2c-0.8,0-1.6-0.1-2.3-0.3L10.2,10.7L10.2,10.7L10.2,10.7z M14.2,17.1 l2.5-7.3c0.5-1.2,0.6-2.1,0.6-2.9c0-0.3,0-0.6-0.1-0.8c0.6,1.2,1,2.5,1,4C18.3,13,16.6,15.7,14.2,17.1L14.2,17.1L14.2,17.1z"/></svg>',
            world: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="#000" d="M1,10.5 L19,10.5"/><path fill="none" stroke="#000" d="M2.35,15.5 L17.65,15.5"/><path fill="none" stroke="#000" d="M2.35,5.5 L17.523,5.5"/><path fill="none" stroke="#000" d="M10,19.46 L9.98,19.46 C7.31,17.33 5.61,14.141 5.61,10.58 C5.61,7.02 7.33,3.83 10,1.7 C10.01,1.7 9.99,1.7 10,1.7 L10,1.7 C12.67,3.83 14.4,7.02 14.4,10.58 C14.4,14.141 12.67,17.33 10,19.46 L10,19.46 L10,19.46 L10,19.46 Z"/><circle fill="none" stroke="#000" cx="10" cy="10.5" r="9"/></svg>',
            xing: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M4.4,4.56 C4.24,4.56 4.11,4.61 4.05,4.72 C3.98,4.83 3.99,4.97 4.07,5.12 L5.82,8.16 L5.82,8.17 L3.06,13.04 C2.99,13.18 2.99,13.33 3.06,13.44 C3.12,13.55 3.24,13.62 3.4,13.62 L6,13.62 C6.39,13.62 6.57,13.36 6.71,13.12 C6.71,13.12 9.41,8.35 9.51,8.16 C9.49,8.14 7.72,5.04 7.72,5.04 C7.58,4.81 7.39,4.56 6.99,4.56 L4.4,4.56 L4.4,4.56 Z"/><path d="M15.3,1 C14.91,1 14.74,1.25 14.6,1.5 C14.6,1.5 9.01,11.42 8.82,11.74 C8.83,11.76 12.51,18.51 12.51,18.51 C12.64,18.74 12.84,19 13.23,19 L15.82,19 C15.98,19 16.1,18.94 16.16,18.83 C16.23,18.72 16.23,18.57 16.16,18.43 L12.5,11.74 L12.5,11.72 L18.25,1.56 C18.32,1.42 18.32,1.27 18.25,1.16 C18.21,1.06 18.08,1 17.93,1 L15.3,1 L15.3,1 Z"/></svg>',
            yelp: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M17.175,14.971c-0.112,0.77-1.686,2.767-2.406,3.054c-0.246,0.1-0.487,0.076-0.675-0.069\tc-0.122-0.096-2.446-3.859-2.446-3.859c-0.194-0.293-0.157-0.682,0.083-0.978c0.234-0.284,0.581-0.393,0.881-0.276\tc0.016,0.01,4.21,1.394,4.332,1.482c0.178,0.148,0.263,0.379,0.225,0.646L17.175,14.971L17.175,14.971z M11.464,10.789\tc-0.203-0.307-0.199-0.666,0.009-0.916c0,0,2.625-3.574,2.745-3.657c0.203-0.135,0.452-0.141,0.69-0.025\tc0.691,0.335,2.085,2.405,2.167,3.199v0.027c0.024,0.271-0.082,0.491-0.273,0.623c-0.132,0.083-4.43,1.155-4.43,1.155\tc-0.322,0.096-0.68-0.06-0.882-0.381L11.464,10.789z M9.475,9.563C9.32,9.609,8.848,9.757,8.269,8.817c0,0-3.916-6.16-4.007-6.351\tc-0.057-0.212,0.011-0.455,0.202-0.65C5.047,1.211,8.21,0.327,9.037,0.529c0.27,0.069,0.457,0.238,0.522,0.479\tc0.047,0.266,0.433,5.982,0.488,7.264C10.098,9.368,9.629,9.517,9.475,9.563z M9.927,19.066c-0.083,0.225-0.273,0.373-0.54,0.421\tc-0.762,0.13-3.15-0.751-3.647-1.342c-0.096-0.131-0.155-0.262-0.167-0.394c-0.011-0.095,0-0.189,0.036-0.272\tc0.061-0.155,2.917-3.538,2.917-3.538c0.214-0.272,0.595-0.355,0.952-0.213c0.345,0.13,0.56,0.428,0.536,0.749\tC10.014,14.479,9.977,18.923,9.927,19.066z M3.495,13.912c-0.235-0.009-0.444-0.148-0.568-0.382c-0.089-0.17-0.151-0.453-0.19-0.794\tC2.63,11.701,2.761,10.144,3.07,9.648c0.145-0.226,0.357-0.345,0.592-0.336c0.154,0,4.255,1.667,4.255,1.667\tc0.321,0.118,0.521,0.453,0.5,0.833c-0.023,0.37-0.236,0.655-0.551,0.738L3.495,13.912z"/></svg>',
            youtube: '<svg width="20" height="20" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M15,4.1c1,0.1,2.3,0,3,0.8c0.8,0.8,0.9,2.1,0.9,3.1C19,9.2,19,10.9,19,12c-0.1,1.1,0,2.4-0.5,3.4c-0.5,1.1-1.4,1.5-2.5,1.6 c-1.2,0.1-8.6,0.1-11,0c-1.1-0.1-2.4-0.1-3.2-1c-0.7-0.8-0.7-2-0.8-3C1,11.8,1,10.1,1,8.9c0-1.1,0-2.4,0.5-3.4C2,4.5,3,4.3,4.1,4.2 C5.3,4.1,12.6,4,15,4.1z M8,7.5v6l5.5-3L8,7.5z"/></svg>',
            oci: '<svg  width="14" height="14" viewBox="0 0 14 14"  xmlns="http://www.w3.org/2000/svg"><g><path style="fill:#FFFFFF;" d="M0.5,21.5L0.6,20c0.3-3.4,2.2-6.5,5.3-8.1c0.7-0.3,1.1-1,1.3-1.7c0.5-2.4,2.1-4.5,4.4-5.5   c1-0.4,2-0.6,3.1-0.6c0.2,0,0.5,0,0.7,0c0.1,0,0.2,0,0.2,0c0.7,0,1.3-0.3,1.7-0.7c1.8-1.9,4.2-3,6.8-3c3.5,0,6.7,2,8.3,5.2   c0.3,0.7,0.9,1.1,1.7,1.3c1.1,0.2,2.1,0.7,3,1.2c4.2,2.7,5.7,8.2,3.3,12.6l-0.4,0.7H0.5z"/><path style="fill:#FFFFFF;" d="M24.1,1c3.4,0,6.4,1.9,7.9,4.9c0.4,0.8,1.1,1.4,2,1.6c1,0.2,2,0.6,2.9,1.2c4,2.5,5.4,7.8,3.1,11.9   L39.8,21H24.3h-2.6h-15H6.5H1.1l0.1-0.9c0.2-3.3,2.1-6.1,5-7.7c0.8-0.4,1.3-1.2,1.5-2c0.4-2.3,2-4.2,4.1-5.1   c0.9-0.4,1.9-0.6,2.9-0.6c0.2,0,0.4,0,0.7,0c0.1,0,0.2,0,0.3,0c0.8,0,1.5-0.3,2-0.9C19.3,2,21.7,1,24.1,1 M24.1,0   c-2.7,0-5.3,1.1-7.2,3.1c-0.3,0.4-0.8,0.6-1.3,0.6c-0.1,0-0.1,0-0.2,0c-0.3,0-0.5,0-0.8,0c-1.1,0-2.2,0.2-3.3,0.7   C9,5.4,7.2,7.6,6.7,10.2c-0.1,0.6-0.5,1-1,1.3c-3.2,1.7-5.3,4.9-5.6,8.5l-0.1,0.9L0,22h1.1h5.4h0.2h15h2.6h15.5h0.6l0.3-0.5   l0.2-0.5c2.5-4.6,1-10.4-3.5-13.2c-1-0.6-2-1.1-3.2-1.3c-0.6-0.1-1.1-0.5-1.3-1C31.2,2.1,27.8,0,24.1,0L24.1,0z"/></g><g><path d="M40,20.5L39.8,21h-18c-3.2,0-5.7-2.6-5.7-5.8h1.7c0,2.3,1.8,4.1,4,4.1h17C40.2,16,39,12,36,10.1   c-0.7-0.5-1.5-0.8-2.3-1c-1.4-0.3-2.6-1.2-3.2-2.5c-1.2-2.4-3.6-3.9-6.3-3.9c-2,0-3.9,0.8-5.2,2.3c-1,1-2.3,1.5-3.8,1.4   c-0.9-0.1-1.8,0.1-2.7,0.4C10.9,7.5,9.7,9,9.4,10.7c-0.3,1.4-1.1,2.5-2.4,3.2C4.9,15,3.4,17,3,19.3h3.5h0.2H16   c0.5,0.7,1,1.2,1.7,1.7h-11H6.5H1.1l0.1-0.9c0.2-3.3,2.1-6.1,5-7.7c0.8-0.4,1.3-1.2,1.5-2c0.4-2.3,2-4.2,4.1-5.1   c1.1-0.5,2.3-0.7,3.5-0.6c0.9,0.1,1.7-0.2,2.3-0.9C19.3,2,21.7,1,24.1,1c3.4,0,6.4,1.9,7.9,4.9c0.4,0.8,1.1,1.4,2,1.6   c1,0.2,2,0.6,2.9,1.2C40.9,11.1,42.2,16.4,40,20.5"/></g></svg>',
            digitalocean: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" width="24" height="24" ><path d="M12.0014 23.9977v-4.6499c4.926 0 8.7494-4.875 6.858-10.0634-.7035-1.9273-2.2222-3.4455-4.1498-4.1482C9.5257 3.2597 4.641 7.0674 4.641 11.9911H0C0 4.1439 7.5929-1.9752 15.8249.595c3.6 1.1287 6.4634 3.9847 7.5787 7.5749C25.9761 16.4198 19.8658 24 12.0014 24z"/><path d="M7.3875 19.3605v-4.6237h4.6259v4.6237zM3.8227 22.923v-3.5625h3.5648v3.5625H3.8227zm0-3.5625H.843V16.383h2.9797v2.9775z"/></svg>',
            cloudstack: '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="24" height="19" viewBox="0 0 24 24" version="1.1">	<g id="surface1">		<path style="fill: #1904da" d="M 2.3 18.5 C 2.3 18.5 2.9 19 4.5 18.9 C 4.5 18.9 4.7 18.9 4.9 18.6 C 4.9 18.6 5.1 18.2 4.4 18.4 C 4.4 18.4 3.5 18.5 2.7 18.1 C 2.7 18.1 1 17.2 0.7 15.8 C 0.7 15.8 0.2 14.4 1 13 C 1 13 1.6 12.1 2.1 11.7 C 2.1 11.7 3.1 10.8 4.5 11.1 C 4.5 11.1 5.3 11.1 6.7 12.2 C 6.7 12.2 7.1 12.4 7 12 C 7 12 6.6 11 5.1 10.7 C 5.1 10.7 5.1 9.5 5.7 8.9 C 5.7 8.9 6.8 7 9.1 7.2 C 9.1 7.2 11.1 7.2 12.3 9.8 C 12.3 9.8 12.6 11 12.4 11.9 L 13.9 11.6 L 12.4 8.9 C 12.4 8.9 11.6 7.1 9.2 6.7 C 9.2 6.7 7.2 6.2 5.4 8.4 C 5.4 8.4 4.6 9.7 4.6 10.6 C 4.6 10.6 2 9.9 0.4 13 C 0.4 13 -1.1 16.4 2.3 18.5" />		<path style="fill: #1904da; fill-rule: nonzero; stroke: none" d="M 15.7 17.5 C 15.7 17.5 18.6 15 15.9 12.5 C 15.9 12.5 16 11.8 15.7 11.5 C 15.7 11.5 15.5 11.2 14.6 11.6 C 14.6 11.6 13.8 11.9 13.1 11.3 L 12.2 11.9 C 12.2 11.9 11.1 12.4 10.6 13.6 C 10.6 13.6 10.2 14.7 10.6 15.1 C 10.6 15.1 10.9 15.2 11 14.9 C 11 14.9 10.9 13.8 11.8 12.9 C 11.8 12.9 13.8 11.3 15.8 13.4 C 15.8 13.4 17 15.1 15.7 16.7 C 15.7 16.7 14.9 17.3 15 17.5 C 15 17.5 15.2 17.7 15.7 17.5 M 8.6 6.7 C 8.6 6.7 8.5 5.7 8.9 4.8 C 8.9 4.8 9 4.4 9.6 3.6 C 9.7 3.5 9.9 3.1 10 2.8 C 10 2.8 10.5 1.3 8.8 1.1 C 8.8 1.1 8.3 1 7.9 1.3 C 7.7 1.5 7.5 1.6 7.3 1.6 C 7.3 1.6 6.5 1.9 6.5 1.4 C 6.5 1.4 6.4 0.6 8.2 0.4 C 8.2 0.4 10.4 0.1 10.7 1.8 C 10.7 1.8 11 2.8 9.7 4.4 C 9.7 4.4 9 5.5 9.2 6.7 C 9.4 7.9 9.2 6.8 9.2 6.8 L 9 6.9 L 8.5 6.7" />		<path style="fill: #1904da" d="M 12.3 8.9 C 12.3 8.9 13.5 8.6 13.7 7.7 L 12 7.6 C 12 7.6 11.5 7.4 11.3 6.6 C 11.3 6.6 10.3 6.1 10.3 5.3 C 10.3 5.3 10.5 4.4 11.3 4.2 C 11.3 4.2 12.2 4 12.4 5.4 C 12.4 5.4 12.8 6.6 12 6.6 C 12 6.6 11.8 7 12.5 7 C 12.5 7 13.2 7.3 13.8 6.8 C 13.8 6.8 14.1 6.5 14.6 6.5 C 14.6 6.5 14.7 6.4 14.5 6.3 C 14.5 6.3 13.4 5.4 13.2 4.1 C 13.2 4.1 12.3 3.9 12.2 3.3 C 12.2 3.3 12 2.4 12.8 2.2 C 12.8 2.2 13.3 2.1 13.6 2.2 C 13.6 2.2 14.3 0.4 16.1 0.1 C 16.1 0.1 17.7 -0.3 18.3 0.9 C 18.3 0.9 18.5 1.5 18.4 2.1 C 18.4 2.1 18.2 2.6 18.4 2.8 C 18.4 2.8 18.9 2.7 19.1 3 C 19.3 3.3 19.4 4 19 4.2 C 19 4.2 19.1 4.7 18.7 5.1 C 18.7 5.1 17.4 5.8 17 6.5 C 17 6.5 16.9 6.6 16.8 6.7 C 16.6 6.8 16.5 6.9 16.3 7 C 16.3 7 16.1 7 15.9 6.9 C 15.9 6.9 15.9 7.2 16.2 7.2 C 16.2 7.2 16.8 7.2 17.4 7 L 21.8 5.4 C 21.8 5.4 21.6 4.9 21.7 4.6 C 21.7 4.6 21.8 4.5 21.9 4.5 C 22.1 4.4 22.3 4.1 22.3 3.9 C 22.3 3.9 22.2 3.3 22.6 3.3 C 22.6 3.3 23 3.3 23 3.8 L 23 4.1 C 23 4.1 23.6 3.8 23.8 4.2 C 23.8 4.2 24.2 5.1 23.8 5.7 C 23.8 5.7 23.1 6.3 22.3 5.9 L 22 5.8 C 22 5.8 16.8 7.9 16.8 8 C 16.8 8 16.4 8.2 16.1 8.7 C 16.1 8.7 15 10.5 14.5 11 C 14.5 11 14.2 11.4 13.9 11.5 L 14 11.8 L 12.9 11.8 L 12.8 10.9 L 12.6 9.3 L 12.3 8.9" />		<path style="fill: rgb(73%, 87%, 92%); fill-rule: nonzero; stroke: none; fill-opacity: 1" d="M 17 1.6 C 17 1.6 17.7 1.1 18 1.6 C 18 1.6 17.9 2.2 18 2.7 C 18 2.7 18 3.4 18.5 3.7 C 18.5 3.7 19 4.2 18.5 4.7 C 18.5 4.7 17.1 5.7 16.9 6.2 C 16.9 6.2 16.2 7.1 15.2 6.5 C 15.2 6.5 13.9 5.7 14.1 4.5 C 14.1 4.5 14.2 4.3 14.6 4.2 C 14.6 4.2 13.7 2.8 14.5 1.9 C 14.5 1.9 15.7 0.4 17 1.6 M 13.3 2.7 C 13.3 2.7 13.1 3.1 13 3.7 C 13 3.7 12.6 3.7 12.6 3.3 C 12.6 3.3 12.5 2.7 13 2.6 C 13 2.6 13.3 2.5 13.3 2.7" />		<path style="fill: rgb(73%, 87%, 92%); fill-rule: nonzero; stroke: none; fill-opacity: 1" d="M 18.3 3.2 C 18.3 3.2 18.6 3 18.7 3.2 C 18.7 3.2 19 3.5 18.9 3.7 C 18.9 3.7 18.7 3.8 18.7 3.7 C 18.7 3.7 18.5 3.5 18.3 3.4 C 18.3 3.4 18.2 3.3 18.3 3.2 M 12.1 5.4 C 12.1 5.4 12 4.8 11.6 4.6 C 11.6 4.6 11.2 4.5 11 4.8 C 11 4.8 10.6 5.2 10.7 5.8 C 10.7 5.8 11 6.3 11.6 6.5 C 11.6 6.5 12 6.6 12.2 6 C 12.2 6 12.3 5.8 12.1 5.4 M 12.7 9.5 C 12.7 9.5 13.6 9.2 14.6 7.9 C 14.6 7.9 14.9 7.5 15.3 7.6 C 15.3 7.6 15.9 7.8 15.5 8.7 C 15.5 8.7 14.8 11 13 11.2 C 13 11.2 13 10 12.7 9.5 M 6.2 11.9 C 6.2 11.9 3.1 11.3 2 13.8 C 2 13.8 1.1 16.8 4.9 17.8 C 4.9 17.8 7.6 18.2 11 17.7 C 11 17.7 14.9 17.2 15.7 16.6 C 15.7 16.6 15.3 17.9 11.6 18.5 C 11.6 18.5 6.3 19.2 4.5 18.9 C 4.5 18.9 4.8 18.9 5 18.5 C 5 18.5 5.1 18.3 4.3 18.4 C 4.3 18.4 2.5 18.6 1.3 16.9 C 1.3 16.9 -0.8 14.2 2.1 11.8 C 2.1 11.8 3.7 10 6.2 11.9" />		<path style="fill: #1904da" d="M 16 3.2 C 16 3.2 16 2.9 15.5 2.8 C 15.5 2.8 15 2.7 14.9 3.2 C 14.9 3.2 14.9 3.4 15.1 3.2 C 15.1 3.2 15.1 3 15.5 3 C 15.5 3 15.8 3 15.9 3.3 C 15.9 3.3 16 3.3 16 3.2 M 16.8 3.3 C 16.8 3.3 16.8 2.9 17.1 2.8 C 17.1 2.8 17.6 2.7 17.7 3.1 C 17.7 3.1 17.8 3.3 17.8 3.3 C 17.8 3.3 17.6 3.3 17.6 3.1 C 17.6 3.1 17.5 2.9 17.2 2.9 C 17.2 2.9 17 3 17 3.2 C 17 3.2 17 3.4 16.8 3.3 M 15.1 4.5 C 15.2 4.4 15.4 4.5 15.4 4.5 C 15.5 4.6 15.7 4.6 15.8 4.7 C 16 4.8 16.2 4.8 16.4 4.8 C 16.5 4.8 16.7 4.9 16.8 4.8 C 16.9 4.8 17 4.8 17.1 4.8 C 17.2 4.8 17.3 4.8 17.4 4.7 C 17.5 4.7 17.6 4.7 17.6 4.6 C 17.7 4.6 17.7 4.6 17.8 4.5 C 17.8 4.5 17.8 4.5 17.9 4.5 C 17.9 4.5 17.9 4.6 17.9 4.6 C 17.9 4.6 17.8 4.7 17.7 4.7 C 17.6 4.8 17.6 4.8 17.5 4.9 C 17.4 4.9 17.2 5.1 17.2 5.2 C 17 5.4 16.8 5.7 16.5 5.9 C 16.3 6 16.2 6 16 6 C 15.8 6 15.6 6 15.5 5.9 C 15.3 5.8 15.2 5.7 15.2 5.6 C 15.2 5.4 15.2 5.2 15.2 5.1 C 15.2 5 15.2 4.8 15.2 4.7 C 15.2 4.6 15.1 4.7 15.1 4.6 C 15.1 4.6 15.1 4.6 15.1 4.5 C 15.1 4.5 15.1 4.5 15.1 4.5 M 16.4 4 C 16.4 4 16.3 4.1 16.3 4.1 C 16.2 4.1 16.1 4 16.1 4 C 16.1 3.9 16.2 3.8 16.3 3.8 C 16.3 3.8 16.4 3.9 16.4 4 M 17 3.9 C 17 4 16.9 4.1 16.8 4.1 C 16.7 4.1 16.7 4 16.7 3.9 C 16.7 3.9 16.7 3.8 16.8 3.8 C 16.9 3.8 17 3.9 17 3.9" />		<path style="fill: #1904da; fill-rule: nonzero; stroke: none" d="M 21.9 5.1 C 21.9 5.1 21.7 4.8 22 4.5 C 22 4.5 22.3 4.4 22.4 4.1 C 22.4 4.1 22.3 3.7 22.5 3.5 C 22.5 3.5 22.8 3.3 22.8 3.7 C 22.8 3.7 22.9 4.1 22.8 4.3 C 22.8 4.3 23.3 4.2 23.5 4.3 C 23.8 4.4 23.8 5.1 23.6 5.4 C 23.6 5.4 23.4 5.9 22.7 5.8 C 22.7 5.8 22.1 5.9 22.1 5.4 C 22.1 5.4 22 5.2 21.9 5.1" />	</g></svg>',
            openstack: '<svg id="logosandtypes_com" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">	<path class="st1" d="M 21 1.3 H 5.2 c -1 0 -1.8 0.8 -1.8 1.8 v 4.4 H 7.8 v -0.7 c 0 -0.5 0.4 -1 1 -1 h 8.7 c 0.5 0 1 0.5 1 1 v 0.7 h 4.4 V 3.1 c 0 -1 -0.8 -1.8 -1.8 -1.8 M 18.4 15.3 c 0 0.5 -0.4 1 -1 1 H 8.8 c -0.5 0 -1 -0.5 -1 -1 v -0.7 H 3.4 V 19 c 0 1 0.8 1.8 1.8 1.8 h 15.8 c 1 0 1.8 -0.8 1.8 -1.8 V 14.6 h -4.4 v 0.7 z M 7.8 8.8 H 3.4 v 4.5 H 7.8 V 8.8 z M 22.8 8.8 h -4.4 v 4.5 h 4.4 V 8.8 z" /></svg>'
        });
    }
    if (typeof window !== "undefined" && window.UIkit) {
        window.UIkit.use(plugin);
    }
    return plugin;
});

(function () {
    "use strict";
    var _$JSONLoader_2 = {
        load: load
    };
    function load(location, callback) {
        var xhr = getXHR();
        xhr.open("GET", location, true);
        xhr.onreadystatechange = createStateChangeListener(xhr, callback);
        xhr.send();
    }
    function createStateChangeListener(xhr, callback) {
        return function () {
            if (xhr.readyState === 4 && xhr.status === 200) {
                try {
                    callback(null, JSON.parse(xhr.responseText));
                } catch (err) {
                    callback(err, null);
                }
            }
        };
    }
    function getXHR() {
        return window.XMLHttpRequest ? new window.XMLHttpRequest() : new ActiveXObject("Microsoft.XMLHTTP");
    }
    "use strict";
    var _$OptionsValidator_3 = function OptionsValidator(params) {
        if (!validateParams(params)) {
            throw new Error("-- OptionsValidator: required options missing");
        }
        if (!(this instanceof OptionsValidator)) {
            return new OptionsValidator(params);
        }
        var requiredOptions = params.required;
        this.getRequiredOptions = function () {
            return requiredOptions;
        };
        this.validate = function (parameters) {
            var errors = [];
            requiredOptions.forEach(function (requiredOptionName) {
                if (typeof parameters[requiredOptionName] === "undefined") {
                    errors.push(requiredOptionName);
                }
            });
            return errors;
        };
        function validateParams(params) {
            if (!params) {
                return false;
            }
            return typeof params.required !== "undefined" && params.required instanceof Array;
        }
    };
    "use strict";
    function fuzzysearch(needle, haystack) {
        var tlen = haystack.length;
        var qlen = needle.length;
        if (qlen > tlen) {
            return false;
        }
        if (qlen === tlen) {
            return needle === haystack;
        }
        outer: for (var i = 0, j = 0; i < qlen; i++) {
            var nch = needle.charCodeAt(i);
            while (j < tlen) {
                if (haystack.charCodeAt(j++) === nch) {
                    continue outer;
                }
            }
            return false;
        }
        return true;
    }
    var _$fuzzysearch_1 = fuzzysearch;
    "use strict";
    var _$FuzzySearchStrategy_5 = new FuzzySearchStrategy();
    function FuzzySearchStrategy() {
        this.matches = function (string, crit) {
            return _$fuzzysearch_1(crit.toLowerCase(), string.toLowerCase());
        };
    }
    "use strict";
    var _$LiteralSearchStrategy_6 = new LiteralSearchStrategy();
    function LiteralSearchStrategy() {
        this.matches = function (str, crit) {
            if (!str) return false;
            str = str.trim().toLowerCase();
            crit = crit.toLowerCase();
            return crit.split(" ").filter(function (word) {
                return str.indexOf(word) >= 0;
            }).length > 0;
        };
    }
    "use strict";
    var _$Repository_4 = {
        put: put,
        clear: clear,
        search: search,
        setOptions: setOptions
    };
    function NoSort() {
        return 0;
    }
    var data = [];
    var opt = {};
    opt.fuzzy = false;
    opt.limit = 10;
    opt.searchStrategy = opt.fuzzy ? _$FuzzySearchStrategy_5 : _$LiteralSearchStrategy_6;
    opt.sort = NoSort;
    function put(data) {
        if (isObject(data)) {
            return addObject(data);
        }
        if (isArray(data)) {
            return addArray(data);
        }
        return undefined;
    }
    function clear() {
        data.length = 0;
        return data;
    }
    function isObject(obj) {
        return Boolean(obj) && Object.prototype.toString.call(obj) === "[object Object]";
    }
    function isArray(obj) {
        return Boolean(obj) && Object.prototype.toString.call(obj) === "[object Array]";
    }
    function addObject(_data) {
        data.push(_data);
        return data;
    }
    function addArray(_data) {
        var added = [];
        clear();
        for (var i = 0, len = _data.length; i < len; i++) {
            if (isObject(_data[i])) {
                added.push(addObject(_data[i]));
            }
        }
        return added;
    }
    function search(crit) {
        if (!crit) {
            return [];
        }
        return findMatches(data, crit, opt.searchStrategy, opt).sort(opt.sort);
    }
    function setOptions(_opt) {
        opt = _opt || {};
        opt.fuzzy = _opt.fuzzy || false;
        opt.limit = _opt.limit || 10;
        opt.searchStrategy = _opt.fuzzy ? _$FuzzySearchStrategy_5 : _$LiteralSearchStrategy_6;
        opt.sort = _opt.sort || NoSort;
    }
    function findMatches(data, crit, strategy, opt) {
        var matches = [];
        for (var i = 0; i < data.length && matches.length < opt.limit; i++) {
            var match = findMatchesInObject(data[i], crit, strategy, opt);
            if (match) {
                matches.push(match);
            }
        }
        return matches;
    }
    function findMatchesInObject(obj, crit, strategy, opt) {
        for (var key in obj) {
            if (!isExcluded(obj[key], opt.exclude) && strategy.matches(obj[key], crit)) {
                return obj;
            }
        }
    }
    function isExcluded(term, excludedTerms) {
        var excluded = false;
        excludedTerms = excludedTerms || [];
        for (var i = 0, len = excludedTerms.length; i < len; i++) {
            var excludedTerm = excludedTerms[i];
            if (!excluded && new RegExp(term).test(excludedTerm)) {
                excluded = true;
            }
        }
        return excluded;
    }
    "use strict";
    var _$Templater_7 = {
        compile: compile,
        setOptions: __setOptions_7
    };
    var options = {};
    options.pattern = /\{(.*?)\}/g;
    options.template = "";
    options.middleware = function () { };
    function __setOptions_7(_options) {
        options.pattern = _options.pattern || options.pattern;
        options.template = _options.template || options.template;
        if (typeof _options.middleware === "function") {
            options.middleware = _options.middleware;
        }
    }
    function compile(data) {
        return options.template.replace(options.pattern, function (match, prop) {
            var value = options.middleware(prop, data[prop], options.template);
            if (typeof value !== "undefined") {
                return value;
            }
            return data[prop] || match;
        });
    }
    "use strict";
    var _$utils_9 = {
        merge: merge,
        isJSON: isJSON
    };
    function merge(defaultParams, mergeParams) {
        var mergedOptions = {};
        for (var option in defaultParams) {
            mergedOptions[option] = defaultParams[option];
            if (typeof mergeParams[option] !== "undefined") {
                mergedOptions[option] = mergeParams[option];
            }
        }
        return mergedOptions;
    }
    function isJSON(json) {
        try {
            if (json instanceof Object && JSON.parse(JSON.stringify(json))) {
                return true;
            }
            return false;
        } catch (err) {
            return false;
        }
    }
    var _$src_8 = {};
    (function (window) {
        "use strict";
        var options = {
            searchInput: null,
            resultsContainer: null,
            json: [],
            success: Function.prototype,
            searchResultTemplate: '<li><a href="{url}" title="{desc}">{title}</a></li>',
            templateMiddleware: Function.prototype,
            sortMiddleware: function () {
                return 0;
            },
            noResultsText: "No results found",
            limit: 10,
            fuzzy: false,
            exclude: []
        };
        var requiredOptions = ["searchInput", "resultsContainer", "json"];
        var optionsValidator = _$OptionsValidator_3({
            required: requiredOptions
        });
        window.SimpleJekyllSearch = function (_options) {
            var errors = optionsValidator.validate(_options);
            if (errors.length > 0) {
                throwError("You must specify the following required options: " + requiredOptions);
            }
            options = _$utils_9.merge(options, _options);
            _$Templater_7.setOptions({
                template: options.searchResultTemplate,
                middleware: options.templateMiddleware
            });
            _$Repository_4.setOptions({
                fuzzy: options.fuzzy,
                limit: options.limit,
                sort: options.sortMiddleware
            });
            if (_$utils_9.isJSON(options.json)) {
                initWithJSON(options.json);
            } else {
                initWithURL(options.json);
            }
            return {
                search: search
            };
        };
        function initWithJSON(json) {
            options.success(json);
            _$Repository_4.put(json);
            registerInput();
        }
        function initWithURL(url) {
            _$JSONLoader_2.load(url, function (err, json) {
                if (err) {
                    throwError("failed to get JSON (" + url + ")");
                }
                initWithJSON(json);
            });
        }
        function emptyResultsContainer() {
            options.resultsContainer.innerHTML = "";
        }
        function appendToResultsContainer(text) {
            options.resultsContainer.innerHTML += text;
        }
        function registerInput() {
            options.searchInput.addEventListener("keyup", function (e) {
                if (isWhitelistedKey(e.which)) {
                    emptyResultsContainer();
                    search(e.target.value);
                }
            });
        }
        function search(query) {
            if (isValidQuery(query)) {
                emptyResultsContainer();
                render(_$Repository_4.search(query));
            }
        }
        function render(results) {
            var len = results.length;
            if (len === 0) {
                return appendToResultsContainer(options.noResultsText);
            }
            dedupeResults(results);
            for (var i = 0; i < len; i++) {
                appendToResultsContainer(_$Templater_7.compile(results[i]));
            }
        }
        function dedupeResults(results) {
            return [...new Set(results)];
        }
        function isValidQuery(query) {
            return query && query.length > 0;
        }
        function isWhitelistedKey(key) {
            return [13, 16, 20, 37, 38, 39, 40, 91].indexOf(key) === -1;
        }
        function throwError(message) {
            throw new Error("SimpleJekyllSearch --- " + message);
        }
    })(window);
})();
