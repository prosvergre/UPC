// Package geo определяет страну сервера. Сейчас — по флагу-эмодзи в имени
// (источники часто его пишут); база IP→страна/город подключается отдельно.
package geo

// CodeFromName ищет в строке флаг-эмодзи (пару региональных индикаторов
// U+1F1E6..U+1F1FF) и возвращает двухбуквенный код страны в верхнем регистре.
func CodeFromName(s string) string {
	var first rune
	for _, r := range s {
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			if first == 0 {
				first = r
				continue
			}
			code := []byte{byte('A' + first - 0x1F1E6), byte('A' + r - 0x1F1E6)}
			return string(code)
		}
		first = 0
	}
	return ""
}
