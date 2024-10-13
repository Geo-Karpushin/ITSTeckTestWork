package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"run/db"
	"run/hashit"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type User struct {
	UUID     uuid.UUID `json:"uuid"`
	Email    string    `json:"email"`
	Password string    `json:"password"`
}

type Token struct {
	UUID      uuid.UUID `json:"uuid"`
	ExpiresAt int64     `json:"expiresAt"`
	jwt.StandardClaims
}

var secretKey []byte

func Init(key string, port string) {
	db.Init()

	http.HandleFunc("/register", registerHandler) // Регистрация пользователя
	http.HandleFunc("/login", loginHandler)       // Авторизация пользователя
	http.HandleFunc("/user/", userHandler)        // Получить модель пользователя

	secretKey = []byte(key)

	fmt.Println("Сервер запущен на порту " + port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Println(err)
	}
}

// Регистрация пользователя
func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	// Проверка на предмет существования пользователя
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = ? OR uuid = ?)", user.Email, user.UUID).Scan(&exists)
	if err != nil || exists {
		http.Error(w, "Пользователь с таким email или UUID уже существует", http.StatusInternalServerError)
		fmt.Println(err)
		return
	}

	// Получаем хеш пароля и соль для сохранения в БД
	hashedPassword, salt := hashit.GeneratePasswordHash(user.Password)

	// Запись пользователя в БД
	err = db.Exec("INSERT INTO users (uuid, email, password, salt) VALUES (?, ?, ?, ?)", user.UUID.String(), user.Email, hashedPassword, salt)
	if err != nil {
		http.Error(w, "Ошибка базы данных", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Пользователь успешно зарегистрирован!"})
}

// Авторизация пользователя
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	var salt, password string
	// Проверка на предмет существования пользователя
	err := db.QueryRow("SELECT salt, password, uuid FROM users WHERE email = ?", user.Email).Scan(&salt, &password, &user.UUID)
	if err != nil {
		if err == db.ErrNoRows {
			http.Error(w, "Неверный email или пароль", http.StatusUnauthorized)
		} else {
			http.Error(w, "Ошибка базы данных", http.StatusInternalServerError)
		}
		return
	}

	// Проверка пароля
	if !hashit.ComparePasswords(password, user.Password, salt) {
		http.Error(w, "Неверный email или пароль", http.StatusUnauthorized)
		return
	}

	// Время истечения токена
	exp := time.Now().Add(7 * 24 * time.Hour).Unix()

	// Создание JWT-токена
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"UUID": user.UUID,
		"exp":  exp,
	})
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	// Возвращаю токен и время истечения
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString, "exp": strconv.Itoa(int(exp))})
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	// Получение uuid из URL
	uuidStr := r.URL.Path[len("/user/"):]

	// Получение токена авторизации
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Отсутствует токен авторизации", http.StatusUnauthorized)
		return
	}
	tokenString = tokenString[len("Bearer "):]

	// Валидация токена
	var claims Token
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil || !token.Valid || claims.UUID.String() != uuidStr {
		http.Error(w, "Ошибка доступа. Проверьте данные и повторите попытку", http.StatusUnauthorized)
		return
	}

	// Получение модели пользователя из БД
	var user User
	err = db.QueryRow("SELECT uuid, email, password FROM users WHERE uuid = ?", claims.UUID.String()).Scan(&user.UUID, &user.Email, &user.Password)
	if err != nil {
		if err == db.ErrNoRows {
			http.Error(w, "Неверный UUID", http.StatusUnauthorized)
		} else {
			http.Error(w, "Ошибка базы данных", http.StatusInternalServerError)
		}
		return
	}

	// Возвращаю модель пользователя
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}
