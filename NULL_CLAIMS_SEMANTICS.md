# 显式 `null` 声明值的语义收敛说明

本文档记录本轮对 JWT 声明（claims）中**显式 JSON `null` 值**处理方式的
一次语义收敛：问题全貌、确定下来的统一语义、治理落点、牺牲面（行为
变更）与理由，以及回归覆盖。所有夹具均使用 HS256 离线自签构造，全程不
依赖网络。

## 1. 背景与漂移全貌

库对外公开两种正式的声明载体，且应用可以在二者间迁移或混用：

- 动态映射容器 `MapClaims`（`map[string]any`，也是不传 claims 时的默认
  载体）；
- 结构体容器 `RegisteredClaims`（以及嵌入它的自定义结构体）。

校验逻辑（`Validator`）本应与底层存储表示解耦，但对于载荷中**显式写出
的 `null`**（例如 `{"exp":null}`），两个载体在解码/取值阶段给出了相反
或互不相同的结局，同一份已正确验签的凭据，生死随实现选择翻转。

收敛前，对同一枚含 `null` 的 HS256 令牌实测如下（`—` 表示该选项不适用）：

| 令牌片段 / 选项 | `MapClaims` 结局 | `RegisteredClaims` 结局 |
| --- | --- | --- |
| `{"exp":null}`（默认，exp 可选） | `ErrInvalidType`，**拒绝** | 无错误，**放行** |
| `{"nbf":null}`（默认） | `ErrInvalidType`，**拒绝** | 无错误，**放行** |
| `{"iat":null}` + `WithIssuedAt()` | `ErrInvalidType`，**拒绝** | 无错误，**放行** |
| `{"iss":null}` + `WithIssuer("me")` | `ErrInvalidType` | `ErrTokenRequiredClaimMissing` |
| `{"sub":null}` + `WithSubject("me")` | `ErrInvalidType` | `ErrTokenRequiredClaimMissing` |
| `{"exp":null}` + `WithExpirationRequired()` | `ErrInvalidType` | `ErrTokenRequiredClaimMissing` |
| `{"aud":null}` | 无错误（已落定的"无值"语义） | 无错误（一致） |

另有第三条支路：把 `NumericDate` 以**值类型**（而非库默认的指针类型）
嵌入自定义结构体时，`{"exp":null}` 会在 JSON 解码阶段直接报错
（`NumericDate.UnmarshalJSON` 把 `null` 交给 `json.Number` 解析失败），
令牌以 `ErrTokenMalformed` 夭折——既不同于指针字段的"置 nil 放行"，也
不同于 map 的类型错误。

### 安全后果

最危险的是第一行。`exp`（以及 `nbf`、`iat`）是时间约束声明：在
`MapClaims` 下一枚带 `exp:null` 的令牌被拒之门外，而在 `RegisteredClaims`
下，`null` 把 `ExpiresAt` 置为 `nil`，校验器据此认为"没有过期时间"，
令牌被当作有效令牌放行。从安全视角看，这枚凭据的过期约束被静默摘除，
等于一枚**永不失效**的令牌。同一个应用只要在两种载体间迁移或混用，
凭据的生死就会随容器选择翻转。

## 2. 收敛后的统一语义

确定一条可预测、与载体无关的规则：

> **显式 JSON `null` 与"声明缺失"同构（claim absent / no value）。**

具体到各声明与各选项：

1. 可选声明（默认情形）上的 `null`：等同于该声明不存在，校验通过，不
   产生错误。
2. 必填/被期望声明上的 `null`：等同于缺失，返回
   `ErrTokenRequiredClaimMissing`，而**不是** `ErrInvalidType`。
3. `WithIssuedAt()` 下的 `iat:null`：没有可比较的时刻，等同于无 `iat`，
   校验通过。
4. 该规则只针对字面量 `null`。任何**非 null 的错误类型**（字符串、布
   尔、对象等）维持原有硬拒绝，绝不因本次收敛被放行。
5. 任何**真实的时间值**语义不变：数字 `exp` 过期依旧 `ErrTokenExpired`
   双载体拒绝，未来 `nbf` 依旧 `ErrTokenNotValidYet`。过期类声明的拒绝
   姿态没有被翻成放行。

这条规则与库内**已经落定**的空值语义完全同构、不冲突：

- `MapClaims.parseClaimsString` 早已把 `aud:null` 当作"无值"返回
  `(nil, nil)`，并有锚定用例 `TestMapClaims_GetAudience` 的 `"null aud"`
  与 `TestVerifyAud` 的 `"Nil String Aud ..."`；
- `ClaimStrings.UnmarshalJSON` 也有 `case nil: return nil`；
- 结构体侧的字符串字段（`iss`/`sub`）在 `null` 下本就保持零值 `""`，
  指针字段（`exp`/`nbf`/`iat`）本就被 `encoding/json` 置 `nil`。

本次只是把日期类与字符串类的 map 取值器、以及值类型 `NumericDate` 的
解码，补齐到这套已经存在的"null 即无值"约定上。

## 3. 治理落点：为什么放在解码/取值层，而不是校验层

改动集中在两个**靠近数据进入点**的位置，`Validator` 一行未动：

- `types.go` 的 `NumericDate.UnmarshalJSON`：识别字面量 `null` 时直接
  返回、保持目标零值，不再把它当作坏数字报错；
- `map_claims.go` 的三个取值器 `parseNumericDate`、`parseString`、
  `parseClaimsString`：把"键存在但值为 `nil`"与"键不存在"统一处理为
  无值。

理由：

1. **符合 v5 的架构取向。** 迁移指南明确，v5 把校验收进 `Validator`，
   目的就是让校验逻辑与声明的存储表示（struct、map 乃至数据库）解耦。
   漂移的根因在解码/取值层对 `null` 的解读不一致，因此在该层消除分
   歧，才能让 `Validator` 真正做到表示无关。若在校验层特判 `null`，
   反而把表示差异又泄漏回校验器，与该设计背道而驰。
2. **改动最小且对称。** 结构体侧的字符串/指针字段由 `encoding/json`
   天然给出零值，无需改动；只需让 map 取值器与值类型日期解码对齐这一
   天然行为即可。
3. **不削弱任何既有拒绝。** 取值器对非 null 的错误类型仍然返回
   `ErrInvalidType`；`NumericDate` 对非 null 的非数字仍然返回解码错误。
   被改变的只有"`null` 被误判为坏类型"这一种情形。

## 4. 牺牲面（行为变更）与取舍

收敛是用一处可预测的语义换来的，以下是明确的不兼容/取舍：

1. **`MapClaims` 下 `exp/nbf/iat/iss/sub` 的显式 `null` 不再报
   `ErrInvalidType`。** 此前依赖"map 中出现 `null` 即报错"这一副作用的
   调用方，会观察到错误消失（可选声明）或错误类型变为
   `ErrTokenRequiredClaimMissing`（必填声明）。这是有意为之：旧行为本
   身就是与结构体载体不一致的漂移源，且没有合理理由让 `null` 比"缺
   失"更严格。
2. **必填场景的错误身份由"类型错误"变为"缺失错误"。** 例如
   `WithExpirationRequired()` 遇 `exp:null`，map 侧从 `ErrInvalidType`
   变为 `ErrTokenRequiredClaimMissing`。二者都是拒绝，安全姿态不变；
   新身份在语义上更准确——`null` 表达的正是"这里没有值"。若有代码用
   `errors.Is(err, ErrInvalidType)` 精确匹配该场景，需要改匹配
   `ErrTokenRequiredClaimMissing` 或同时匹配二者。
3. **值类型 `NumericDate` 遇 `null` 不再解码失败。** 此前会以
   `ErrTokenMalformed` 夭折的令牌，现在能解码（字段保持零值）。库官方
   `RegisteredClaims` 用的是指针 `*NumericDate`，值类型属于较少见的自
   定义嵌入；新行为使其与指针形态、map 形态三者一致。
4. **未统一"非 null 错误类型"在两载体间的错误身份。** 字符串 `exp`
   等情形，map 报 `ErrInvalidType`、结构体在 JSON 解码阶段报
   `ErrTokenMalformed`，这是先于本次工作存在的结构性差异（见既有
   `parser_test.go` 中 `"aud":1` 用例）。本轮范围严格限定为 `null` 语
   义，不扩大到一般类型错误，以免引入额外的、与本问题无关的破坏面。
   两者均为硬拒绝，不存在放行风险。
5. **没有新增解析选项来保留旧行为。** 刻意不引入"严格 null"开关：保留
   两套可切换语义只会让漂移以配置项的形式继续存在，违背"收敛成一套
   可预测语义"的目标。

## 5. 锚定用例与不冲突证明

以下库内既定语义及其测试在改动后保持全绿，未被推翻：

- `exp: 0`（1970-01-01）必须判过期：`TestMapClaims_GetExpirationTime_ZeroIsExpired`
  仍通过，数字 0 不与 `null` 混淆；
- 字符串 `exp` 必须是 `ErrInvalidType`：
  `TestMapClaims_GetExpirationTime_StringIsInvalidType` 仍通过；
- `aud` 的 null/缺失即无值：`TestMapClaims_GetAudience`、`TestVerifyAud`
  仍通过，本次仅同步了注释，行为未改；
- 必填缺失语义：`"rejects if exp is required but missing"` 等 parser
  用例仍通过；
- 全量存量测试在 `-count=1` 下保持通过。

## 6. 回归覆盖

新增/补强的测试（均为离线、无外部依赖）：

- `null_semantics_test.go`（外部包，端到端走真实 parse+验签+validate）：
  - `TestNullClaim_MapAndStructParity`：对六个注册声明的 `null`，在
    `MapClaims` 与 `RegisteredClaims` 下逐一对拍有效性、错误身份与
    `token.Valid`；覆盖可选放行、必填/被期望缺失、`iat` 校验，以及数字
    过期/未来 `nbf` 的拒绝守卫；
  - `TestNullClaim_WrongTypeStillRejected`：钉住非 null 错误类型在两种
    载体下都被硬拒绝（各自的既有错误身份）。
- `map_claims_test.go`（包内）：
  - `TestMapClaims_NullNumericDateIsAbsent`、
    `TestMapClaims_NullStringIsAbsent`：null 与缺失等价，且错误类型仍
    拒绝；
  - `TestMapClaims_NullValidationParity`：经公开 `Validator` 入口验证
    null 的可选/必填/`iat` 结局；
  - `parseString` 表驱动补充 `"explicit null"` 用例。
- `types_test.go`：`TestNumericDate_NullIsNoValue` 覆盖值类型与指针两
  种嵌入形态下 `null` 的解码，以及数字值正常解码、非数字仍报错。

## 7. 变更文件清单

- `types.go`：`NumericDate.UnmarshalJSON` 增加 `null` 短路。
- `map_claims.go`：`parseNumericDate`、`parseString` 统一 null/缺失；
  `parseClaimsString` 同步注释（行为原本已正确）。
- `types_test.go`、`map_claims_test.go`、`null_semantics_test.go`：回归
  与对拍用例。
- 本文档；`MIGRATION_GUIDE.md` 增补一段可迁移性说明。
