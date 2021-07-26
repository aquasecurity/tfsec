package ascii

import (
	"image/gif"
	"io"
	"net/http"
	"os"
)

func FromURL(url string) (*Renderer, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return FromReader(resp.Body)
}

func FromFile(path string) (*Renderer, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return FromReader(file)
}

func FromReader(reader io.Reader) (*Renderer, error) {
	img, err := gif.DecodeAll(reader)
	if err != nil {
		return nil, err
	}

	return &Renderer{
		image: img,
	}, nil
}
