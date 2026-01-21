package core

import "SparkProxy/core/identity"

type PasskeyCredential = identity.PasskeyCredential

func ListPasskeyCredentials(username string) []identity.PasskeyCredential {
	return identity.ListPasskeyCredentials(username)
}

func GetPasskeyCredentialByID(credentialID []byte) *identity.PasskeyCredential {
	return identity.GetPasskeyCredentialByID(credentialID)
}

func CreatePasskeyCredential(userID, username string, credentialID, publicKey []byte, signCount uint32, deviceType string) (identity.PasskeyCredential, error) {
	return identity.CreatePasskeyCredential(userID, username, credentialID, publicKey, signCount, deviceType)
}

func UpdatePasskeySignCount(credentialID []byte, newSignCount uint32) error {
	return identity.UpdatePasskeySignCount(credentialID, newSignCount)
}

func DeletePasskeyCredential(id string) error {
	return identity.DeletePasskeyCredential(id)
}

func DeletePasskeyCredentialsByUser(username string) error {
	return identity.DeletePasskeyCredentialsByUser(username)
}
