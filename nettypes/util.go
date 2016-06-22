package nettypes

func padLeft(str, pad string, length int) string {
	for ; length > 0; length-- {
		str = pad + str
	}
	return str
}
