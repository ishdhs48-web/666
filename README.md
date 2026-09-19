# InfiniteHP

## Как собрать через GitHub (без установки чего-либо)

1. Зайди на github.com → **New repository** → назови как хочешь → Create
2. Загрузи все файлы из этого архива (dllmain.cpp, inject.cpp, и папку .github целиком)
3. Перейди во вкладку **Actions** → слева выбери **Build InfiniteHP** → **Run workflow**
4. Подожди ~1-2 минуты
5. Кликни на завершённый run → внизу страницы раздел **Artifacts** → скачай **InfiniteHP-build.zip**
6. Внутри: `InfiniteHP.dll` + `inject.exe`

## Использование

```
inject.exe  GameName.exe  C:\полный\путь\InfiniteHP.dll
```
Запускать от имени администратора. Игра должна уже быть запущена.
