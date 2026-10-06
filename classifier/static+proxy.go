package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
)

func main() {
	targetURL, _ := url.Parse("http://localhost:8090")
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	staticDir := "./static"

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 1. Формируем путь, где файл ДОЛЖЕН лежать на диске
		// Например, запрос "/" превратится в "./static/index.html" (благодаря http.Dir ниже)
		// Запрос "/css/style.css" превратится в "./static/css/style.css"
		requestedPath := filepath.Join(staticDir, r.URL.Path)

		// Если запросили корень "/", проверяем наличие index.html
		if r.URL.Path == "/" {
			requestedPath = filepath.Join(staticDir, "index.html")
		}

		// 2. Физически проверяем: существует ли такой файл или папка на диске?
		fileInfo, err := os.Stat(requestedPath)
		
		if err == nil && !fileInfo.IsDir() {
			// ФАЙЛ СУЩЕСТВУЕТ -> Отдаем статику
			log.Printf("[СТАТИКА] Отдаем файл: %s", r.URL.Path)
			http.FileServer(http.Dir(staticDir)).ServeHTTP(w, r)
			return
		}

		// 3. ФАЙЛА НЕТ НА ДИСКЕ -> Значит это "просто эндпоинт" (API, роут бэкенда и т.д.)
		// Перенаправляем весь request/response на порт 8090
		log.Printf("[ПРОКСИ] Направляем роут %s %s на :8090", r.Method, r.URL.Path)
		r.Host = targetURL.Host
		proxy.ServeHTTP(w, r)
	})

	log.Println("Сервер запущен на :8080...")
	http.ListenAndServe(":8080", nil)
}
