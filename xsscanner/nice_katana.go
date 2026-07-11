// nice_katana.go
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	gray  = "\033[90m"
	reset = "\033[0m"
)

func runNiceKatanaBatch(targets []string, outDir string) {
	if len(targets) == 0 {
		return
	}

	// ۱. ساخت فایل موقت حاوی تمام تارگت‌ها برای پاس دادن به کاتانا
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

	// چون لیست گروهی است، اسم فایل خروجی را عمومی‌تر می‌گذاریم
	katanaOutput := filepath.Join(outDir, "katana_batch_output.txt")
	extFilter := "json,js,fnt,ogg,css,jpg,jpeg,png,svg,img,gif,exe,mp4,flv,pdf,doc,ogv,webm,wmv,webp,mov,mp3,m4a,m4p,ppt,pptx,scss,tif,tiff,ttf,otf,woff,woff2,bmp,ico,eot,htc,swf,rtf,image,rf,txt,ml,ip"

	// متغیرهای رنگ
	gray := "\033[1;30m"
	reset := "\033[0m"

	fmt.Printf("%sExecuting Katana (Batch mode, rate-limited) for %d targets%s\n", gray, len(targets), reset)

	// ۲. استفاده از تمام فلگ‌های اختصاصی خودت
	ctxArgs := []string{
		"-list", tmpFile.Name(), // به جای -u فایل لیست را دادیم
		"-d", "2",
		"-js-crawl",
		"-jsluice",
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

	cmd := exec.Command("katana", ctxArgs...)

	// ۳. داینامیک کردن تایم‌اوت: ۱۵ دقیقه برای هر تارگت داخل لیست
	timeoutDuration := time.Duration(15*len(targets)) * time.Minute
	// قرار دادن سقف مکانیزم جلوگیری از قفل شدن (مثلا حداکثر ۳ ساعت برای کل لیست)
	if timeoutDuration > 3*time.Hour {
		timeoutDuration = 3 * time.Hour
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		if err != nil {
			fmt.Printf("Error running katana batch: %v\n", err)
			return
		}
	case <-time.After(timeoutDuration):
		fmt.Printf("%skatana timed out for batch after %v, killing process%s\n", gray, timeoutDuration, reset)
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return
	}

	// ۴. شمارش خطوط خروجی نهایی
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

func main() {
	var outDir string
	flag.StringVar(&outDir, "o", "results/katana", "Output directory")

	// نکته: اگر فلگ‌های دیگری مثل timeout یا jsluice در نسخه اصلی داری، اینجا تعریفشان کن
	flag.Parse()

	var targets []string
	if flag.NArg() > 0 {
		arg := flag.Arg(0)
		if info, err := os.Stat(arg); err == nil && !info.IsDir() {
			file, _ := os.Open(arg)
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				// جلوگیری از اضافه شدن خطوط خالی
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

	// متغیرهای رنگ برای لاگ
	gray := "\033[1;30m"
	reset := "\033[0m"

	// لاگ تایید گرفتن کل لیست
	fmt.Printf("%s[STARTUP] nice_katana processing batch size: %d URLs%s\n", gray, len(targets), reset)

	// حذف حلقه for و ارسال کل آرایه به تابع پردازش گروهی
	// اگر فلگ‌های دیگری مثل کانکارنسی یا تایم‌اوت داری، به پارامترهای این تابع اضافه‌شان کن
	runNiceKatanaBatch(targets, outDir)
}
