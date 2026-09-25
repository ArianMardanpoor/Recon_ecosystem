package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// بررسی پشتیبانی باینری کاتانا از فلگ jsluice
func supportsJsluice() bool {
	cmd := exec.Command("katana", "-h")
	out, _ := cmd.CombinedOutput()
	return strings.Contains(string(out), "-jsluice")
}

func main() {
	var outDir string
	flag.StringVar(&outDir, "o", "results/katana", "Output directory")

	// اضافه شدن فلگ verbose
	var verbose bool
	flag.BoolVar(&verbose, "verbose", false, "Print full katana command before execution")

	flag.Parse()

	var targets []string
	if flag.NArg() > 0 {
		arg := flag.Arg(0)
		if info, err := os.Stat(arg); err == nil && !info.IsDir() {
			file, _ := os.Open(arg)
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				val := strings.TrimSpace(scanner.Text())
				if val != "" {
					targets = append(targets, val)
				}
			}
			file.Close()
		} else {
			targets = append(targets, arg)
		}
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				val := strings.TrimSpace(scanner.Text())
				if val != "" {
					targets = append(targets, val)
				}
			}
		}
	}

	if len(targets) == 0 {
		fmt.Println("Usage:")
		fmt.Println("  echo domain.com | nice_katana")
		fmt.Println("  nice_katana domain.com")
		fmt.Println("  nice_katana domains.txt")
		return
	}

	gray := "\033[1;30m"
	reset := "\033[0m"

	fmt.Printf("%s[STARTUP] nice_katana processing batch size: %d URLs%s\n", gray, len(targets), reset)

	runNiceKatanaBatch(targets, outDir, verbose)
}

func runNiceKatanaBatch(targets []string, outDir string, verbose bool) {
	if len(targets) == 0 {
		return
	}

	tmpFile, err := os.CreateTemp("", "katana_targets_*.txt")
	if err != nil {
		fmt.Printf("Error creating temp file: %v\n", err)
		return
	}
	defer os.Remove(tmpFile.Name())

	for _, t := range targets {
		tmpFile.WriteString(t + "\n")
	}
	tmpFile.Close()

	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Printf("Error creating directory: %v\n", err)
		return
	}

	katanaOutput := filepath.Join(outDir, "katana_batch_output.txt")

	// اصلاح رشته فیلتر (ml و ip به xml و zip تغییر کردند)
// رفع باگ اکستنشن‌های کراپت شده
	extFilter := "json,js,fnt,ogg,css,jpg,jpeg,png,svg,img,gif,exe,mp4,flv,pdf,doc,ogv,webm,wmv,webp,mov,mp3,m4a,m4p,ppt,pptx,scss,tif,tiff,ttf,otf,woff,woff2,bmp,ico,eot,htc,swf,rtf,image,rf,txt,xml,zip"
	gray := "\033[1;30m"
	yellow := "\033[1;33m"
	reset := "\033[0m"

	fmt.Printf("%sExecuting Katana (Batch mode, rate-limited) for %d targets%s\n", gray, len(targets), reset)

	ctxArgs := []string{
		"-list", tmpFile.Name(),
		"-d", "2",
		"-js-crawl",
		"-known-files", "all",
		"-automatic-form-fill",
		"-extension-filter", extFilter,
		"-c", "4",
		"-rl", "12",
		"-delay", "250",
		"-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"-retry", "3",
		"-timeout", "4",
		"-silent",
		"-o", katanaOutput,
	}

	// بررسی و افزودن امن فلگ jsluice
	if supportsJsluice() {
		ctxArgs = append(ctxArgs, "-jsluice")
	} else {
		fmt.Printf("%s[WARNING] Installed katana binary does not support -jsluice flag. Skipping it.%s\n", yellow, reset)
	}

	cmd := exec.Command("katana", ctxArgs...)

	// گرفتن خروجی Stderr
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	// نمایش دستور کامل در حالت verbose
	if verbose {
		fmt.Printf("%s[VERBOSE] Command: katana %s%s\n", gray, strings.Join(ctxArgs, " "), reset)
	}

	timeoutDuration := time.Duration(15*len(targets)) * time.Minute
	if timeoutDuration > 3*time.Hour {
		timeoutDuration = 3 * time.Hour
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		if err != nil {
			fmt.Printf("Error running katana batch: %v\n", err)
			// در صورت خطا، محتوای Stderr به طور کامل چاپ می‌شود
			if stderrBuf.Len() > 0 {
				fmt.Printf("Katana Stderr:\n%s\n", stderrBuf.String())
			}
			return
		}
	case <-time.After(timeoutDuration):
		fmt.Printf("%skatana timed out for batch after %v, killing process%s\n", gray, timeoutDuration, reset)
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return
	}

	file, _ := os.Open(katanaOutput)
	count := 0
	if file != nil {
		sc := bufio.NewScanner(file)
		for sc.Scan() {
			count++
		}
		file.Close()
	}

	fmt.Printf("%sdone for batch, results: %d saved to %s%s\n", gray, count, katanaOutput, reset)
}
