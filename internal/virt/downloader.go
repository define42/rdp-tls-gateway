package virt

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type progressReader struct {
	reader      io.Reader
	total       int64
	downloaded  int64
	lastPrinted time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.reader.Read(b)
	p.downloaded += int64(n)

	// Print at most every 200ms
	if time.Since(p.lastPrinted) > 200*time.Millisecond {
		p.printProgress()
		p.lastPrinted = time.Now()
	}

	return n, err
}

func (p *progressReader) printProgress() {
	if p.total > 0 {
		percent := float64(p.downloaded) / float64(p.total) * 100
		fmt.Printf("\rDownloading... %.1f%% (%d / %d bytes)",
			percent, p.downloaded, p.total)
	} else {
		fmt.Printf("\rDownloading... %d bytes", p.downloaded)
	}
}

func downloadWithProgress(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	pr := &progressReader{
		reader: resp.Body,
		total:  resp.ContentLength,
	}

	_, err = io.Copy(out, pr)
	fmt.Println("\nDownload complete")
	return err
}
