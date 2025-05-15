# CrowdStrike Query Language Grammar Subset

## Overview

This grammar represents a subset of the CrowdStrike Query Language (CQL), formerly known as the LogScale Query Language (LQL). This guide is intended for programmatically generating LogScale queries—not for parsing them.

## Grammar Rules

### Query and Pipeline

```
Query ::= Pipeline?

Pipeline ::= PipelineStep ( '|' PipelineStep )*

PipelineStep ::=
    Filter
    | FunctionCall
    | EvalFunctionShorthand
    | EvalShorthand
    | FieldShorthand
    | Case
    | Match
    | StatsShorthand
    | SavedQuery
```

### Filters

```
Filter ::= LogicalAndFilter

LogicalAndFilter ::= LogicalOrFilter ('AND'? LogicalOrFilter)*

LogicalOrFilter ::= UnaryFilter ('OR' UnaryFilter)*

UnaryFilter ::= 'NOT'* PrimaryFilter

PrimaryFilter ::=
    FieldName '=' EqualityPattern |
    FieldName 'like' LikePattern |
    FieldName '!=' EqualityPattern |
    FieldName '<' Number |
    FieldName '<=' Number |
    FieldName '>' Number |
    FieldName '>=' Number |
    FreeTextPattern |
    'true' |
    'false' |
    '(' Filter ')'

FieldName ::= UnquotedFieldName | QuotedString
```

**Important Notes:**
- Implicit AND is supported in the Filter production
- Example: `foo < 42 + 3` means `(foo < 42) AND "*+*" AND "*3*"`
- `LogicalOrFilter1 LogicalOrFilter2` is shorthand for `LogicalOrFilter1 AND LogicalOrFilter2`

### Patterns

```
FreeTextPattern ::= UnquotedPattern | QuotedString | Regex | QueryParameter

LikePattern ::= UnquotedPattern | QuotedString | QueryParameter

EqualityPattern ::= AnchoredPattern | Regex | QueryParameter

AnchoredPattern ::= UnquotedPattern | QuotedString
```

**Pattern Behavior:**
- When UnquotedPattern or QuotedString are used as patterns, the asterisk character (`*`) is a wildcard
- Patterns are case-sensitive by default
- Regular expressions can be used to disable case sensitivity using the `i` flag

#### Anchored Patterns

- A pattern is "anchored" if it must match the entire string
- EqualityPattern and AnchoredPattern are always anchored
- FreeTextPattern and LikePattern are not anchored (except for Regex)
- When not anchored, patterns are equivalent to having `*` prepended and appended

### Query Parameters

```
QueryParameter ::=
    '?' QueryParameterName
    | '?{' QueryParameterName '=' QueryParameterDefaultValue '}'

QueryParameterName ::= UnquotedPattern | QuotedString

QueryParameterDefaultValue ::= UnquotedPattern | QuotedString
```

### Unquoted Strings

- An UnquotedPattern is a non-empty sequence of characters
- An UnquotedFieldName is a non-empty sequence of characters
- Cannot start with `/` (one slash) and cannot end with `//` (two slashes)
- UnquotedPattern supports the `*` wildcard character
- UnquotedFieldName supports JSON array index syntax (e.g., `foo.bar[42]`)

### Quoted Strings

- A QuotedString is a sequence of characters surrounded by `"`
- Cannot span multiple lines, but `\n` can be used to include newlines
- `\"` can be used to include `"` in the string
- `\\` can be used to include the character `\`

### Regular Expressions

```
Regex
```

- A sequence of characters surrounded by `/`
- Cannot span multiple lines
- `\/` can be used to include `/` in the regular expression
- Can be followed by flags: `d`, `m`, and `i`
- Regular expressions are not anchored by default

### Function Call

```
FunctionCall ::= FunctionName '(' FunctionArguments? ')'

FunctionArguments ::=
    NamedFunctionArgument (',' FunctionArguments)? |
    UnnamedFunctionArgument (',' FunctionArguments)?

NamedFunctionArgument ::= FieldName '=' Expression

UnnamedFunctionArgument ::= Expression
```

### Expression

```
Expression ::=
    Expression ComparisonOperator AdditiveExpression |
    AdditiveExpression

ComparisonOperator ::= '==' | '!=' | '>=' | '<=' | '>' | '<'

AdditiveExpression ::=
    AdditiveExpression AdditiveOperator MultiplicativeExpression |
    MultiplicativeExpression

AdditiveOperator ::= '+' | '-'

MultiplicativeExpression ::=
    MultiplicativeExpression MultiplicativeOperator UnaryExpression |
    UnaryExpression

MultiplicativeOperator ::= '*' | '/' | '%'

UnaryExpression ::= UnaryOperator? PrimaryExpression

UnaryOperator ::= '-' | '!'

PrimaryExpression ::=
    '(' Expression ')' |
    Subquery |
    FunctionCall |
    ArrayExpression |
    QueryParameter |
    BareWord |
    QuotedString

Subquery ::= '{' Pipeline '}'
```

### Array Expression

```
ArrayExpression ::= '[' (ArrayElement (',' ArrayElement)* )? ']'

ArrayElement ::= EvalFunctionShorthand | Expression
```

### Eval Shorthand

```
EvalFunctionShorthand ::= FieldName ':=' FunctionCall

EvalShorthand ::= FieldName ':=' Expression
```

### Field Shorthand

```
FieldShorthand ::= FieldName '=~' FunctionCall
```

### Case

```
Case ::= 'case' '{' Pipeline (';' Pipeline)* '}'
```

### Match

```
Match ::= FieldName 'match' '{' MatchPipeline (';' MatchPipeline)* '}'

MatchPipeline ::= MatchGuard => Pipeline

MatchGuard ::= '*' | Regex | FunctionCall | QueryParameter | AnchoredPattern
```

### Saved Query

```
SavedQuery ::= '$' (UnquotedPattern | QuotedString) '(' SavedQueryArguments? ')'

SavedQueryArguments ::= SavedQueryArgument (',' SavedQueryArgument)*

SavedQueryArgument ::=
    (UnquotedPattern | QuotedString) '=' (UnquotedPattern | QuotedString)
```

### Stats Shorthand

```
StatsShorthand ::= ArrayExpression
```

## Important Quirks

### Slashes

- Slash (`/`) is used for comments, regular expression literals, and division
- `https://www.example.com/` is valid and equivalent to `"*https://www.example.com/*"`
- `/fisk/i` is a valid regex query
- `a:=m/fisk/i` divides field `m` by fields `fisk` and `i`

### Comparison Operators

- The left side of comparison in PrimaryFilter is always a field name
- The right side is never a field name
- `myField = myOtherField` checks if myField holds the value "myOtherField"
- Use `test(myField == myOtherField)` to compare field values

### Precedence

- AND/OR precedence is reversed compared to most programming languages
- This is due to implicit AND behavior

### Reserved Words

- Function names are reserved words
- Some reserved words are not enforced consistently
- Example: `test` is a syntax error, but `test=fisk` is valid

## Best Practices

1. Avoid using implicit AND
2. Prefer `|` over `AND` to avoid precedence confusion
3. Use parentheses around logical expressions
4. Avoid unquoted strings when possible
5. Quote patterns to avoid ambiguity

## Key Differences from Full Grammar

- This subset excludes several quirks present in the full LogScale parser
- Not sufficient for parsing LogScale queries
- Designed specifically for programmatic query generation
