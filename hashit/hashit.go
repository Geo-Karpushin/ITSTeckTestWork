package hashit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// Генерация соли
func getSalt() string {
	salt := make([]byte, 16)
	rand.Read(salt)
	return string(salt)
}

// Получения хеша строки
func getHash(in string) (sha string) {
	hasher := sha256.New()
	hasher.Write([]byte(in))
	sha = base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	return
}

// Генерация хеша пароля и соли для БД
func GeneratePasswordHash(password string) (hash, salt string) {
	salt = getSalt()
	hash = getHash(password + salt)
	return
}

// Сравнение пароля из БД и введённого пользователем
func ComparePasswords(real, test, salt string) bool {
	return real == getHash(test+salt)
}
