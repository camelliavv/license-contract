package contract

// Product and feature codes used by the authorization application. Product is
// the top-level license type; feature codes represent the capabilities enabled
// within that type.
const (
	FeatureSCT  = "SCT"  // 速鉴
	FeatureCPS  = "CPS"  // 密评
	FeatureRISK = "RISK" // 风评
	FeatureAPP  = "APP"  // 速鉴 APP
	FeatureDST  = "DST"  // 数据安全
	FeatureSCA  = "SCA"  // 质衡
)

// Limit keys used by the authorization application. Values are upper bounds
// carried in LicensePayload.Limits; current usage is not part of a license.
const (
	LimitUsersTotal           = "user_total"             // 用户总数
	LimitEqualProtection      = "equal_protection"       // 等保数量
	LimitCryptoAssessment     = "crypto_assessment"      // 密评数量
	LimitDataSecurity         = "data_security"          // 数据安全数量
	LimitQualityAssessment    = "quality_assessment"     // 质衡数量
	LimitReportQualityControl = "report_quality_control" // 报告质控
)
