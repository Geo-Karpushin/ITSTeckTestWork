package auth

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
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

var db *sql.DB

var secretKey []byte

func Init(key string, port string) {
	var err error

	// Подключение к БД
	db, err = sql.Open("sqlite3", "auth.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// При необходимости, создаю таблицу
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		uuid TEXT PRIMARY KEY,
		email TEXT UNIQUE,
		password TEXT
	)`)
	if err != nil {
		panic(err)
	}

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
		return
	}

	// Запись пользователя в БД
	_, err = db.Exec("INSERT INTO users (uuid, email, password) VALUES (?, ?, ?)", user.UUID.String(), user.Email, user.Password)
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

	// Проверка на предмет существования пользователя
	err := db.QueryRow("SELECT uuid FROM users WHERE email = ? and password = ?", user.Email, user.Password).Scan(&user.UUID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Неверный email или пароль", http.StatusUnauthorized)
		} else {
			http.Error(w, "Ошибка базы данных", http.StatusInternalServerError)
		}
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
	err = db.QueryRow("SELECT * FROM users WHERE uuid = ?", claims.UUID.String()).Scan(&user.UUID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
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
