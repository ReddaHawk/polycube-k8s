package utils

import (

)

func CreatePeer(nameService string, namePort string) string{
	return "\""+nameService+":"+namePort+"\""
}