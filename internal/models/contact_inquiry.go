package models

import "time"

// ContactInquiry mirrors vault3_contact_inquiry (see scripts/sql/004.sql).
type ContactInquiry struct {
	ID        string    `json:"id" db:"Vault3ContactInquiryID"`
	Name      string    `json:"name" db:"Vault3ContactInquiryName"`
	Email     string    `json:"email" db:"Vault3ContactInquiryEmail"`
	Message   string    `json:"message" db:"Vault3ContactInquiryMessage"`
	IPAddress string    `json:"ipAddress,omitempty" db:"Vault3ContactInquiryIpAddressEnc"`
	UserAgent string    `json:"userAgent,omitempty" db:"Vault3ContactInquiryUserAgentEnc"`
	CreatedAt time.Time `json:"createdAt" db:"Vault3ContactInquiryCreatedAt"`
}
