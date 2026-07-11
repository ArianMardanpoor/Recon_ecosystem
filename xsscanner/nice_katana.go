// nice_katana.go
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

const (
	gray  = "\033[90m"
	reset = "\033[0m"
)

<<<<<<< HEAD
func runNiceKatanaBatch(targets []string, outDir string) {
=======
// تابع runNiceKatanaBatch جایگزین تابع قبلی شده و یک لیست از تارگت‌ها دریافت می‌کند
func runNiceKatanaBatch(targets []string, outDir string, useJsluice bool, timeoutVal time.Duration, concurrency, rateLimit int) {
>>>>>>> 585fbcebeac7efd4988634e5867d1ba8e682d808
	if len(targets) == 0 {
		return
	}

<<<<<<< HEAD
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
=======
	fmt.Printf("%srunning katana for batch of %d URLs%s\n", gray, len(targets), reset)
>>>>>>> 585fbcebeac7efd4988634e5867d1ba8e682d808

	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Printf("Error creating directory: %v\n", err)
		return
	}

<<<<<<< HEAD
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
=======
	// ۱. ایجاد فایل موقت برای پاس دادن به فلگ list-
	tmpFile, err := os.CreateTemp("", "katana_targets_*.txt")
	if err != nil {
		fmt.Printf("Error creating temp file: %v\n", err)
		return
	}
	tmpFileName := tmpFile.Name()
	// پاک کردن فایل موقت پس از اتمام اجرای تابع
	defer os.Remove(tmpFileName) 

	// نوشتن تمام تارگت‌ها در فایل موقت
	for _, t := range targets {
		if t != "" {
			tmpFile.WriteString(t + "\n")
		}
	}
	tmpFile.Close()

	// ایجاد نام خروجی یکتا بر اساس تایم‌استمپ برای batch
	timestamp := time.Now().Unix()
	katanaOutput := filepath.Join(outDir, fmt.Sprintf("katana_batch_%d.txt", timestamp))

	extFilter := "json,js,fnt,ogg,css,jpg,jpeg,png,svg,img,gif,exe,mp4,flv,pdf,doc,ogv,webm,wmv,webp,mov,mp3,m4a,m4p,ppt,pptx,scss,tif,tiff,ttf,otf,woff,woff2,bmp,ico,eot,htc,swf,rtf,image,rf,txt,xml,zip"

	fmt.Printf("%sExecuting Katana (Batch mode) for %d targets%s\n", gray, len(targets), reset)

	// استفاده از -list و مقادیر داینامیک -c و -rl
	ctxArgs := []string{
		"-list", tmpFileName,
>>>>>>> 585fbcebeac7efd4988634e5867d1ba8e682d808
		"-d", "2",
		"-js-crawl",
		"-known-files", "all",
		"-automatic-form-fill",
		"-extension-filter", extFilter,
<<<<<<< HEAD
		"-c", "4",
		"-rl", "12",
=======
		"-c", fmt.Sprintf("%d", concurrency),
		"-rl", fmt.Sprintf("%d", rateLimit),
>>>>>>> 585fbcebeac7efd4988634e5867d1ba8e682d808
		"-delay", "250",
		"-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"-retry", "3",
		"-timeout", "4",
		"-silent",
		"-o", katanaOutput,
	}

	if useJsluice {
		ctxArgs = append(ctxArgs, "-jsluice")
	}

	cmd := exec.Command("katana", ctxArgs...)

<<<<<<< HEAD
	// ۳. داینامیک کردن تایم‌اوت: ۱۵ دقیقه برای هر تارگت داخل لیست
	timeoutDuration := time.Duration(15*len(targets)) * time.Minute
	// قرار دادن سقف مکانیزم جلوگیری از قفل شدن (مثلا حداکثر ۳ ساعت برای کل لیست)
	if timeoutDuration > 3*time.Hour {
		timeoutDuration = 3 * time.Hour
	}
=======
	// حفظ ساختار کپچر کردن Stderr/Stdout از اصلاح قبلی
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
>>>>>>> 585fbcebeac7efd4988634e5867d1ba8e682d808

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		if err != nil {
			fmt.Printf("Error running katana batch: %v\n", err)
<<<<<<< HEAD
			return
		}
	case <-time.After(timeoutDuration):
		fmt.Printf("%skatana timed out for batch after %v, killing process%s\n", gray, timeoutDuration, reset)
=======
			if stderrBuf.Len() > 0 {
				fmt.Printf("Stderr Output:\n%s\n", stderrBuf.String())
			}
			if stdoutBuf.Len() > 0 {
				fmt.Printf("Stdout Output:\n%s\n", stdoutBuf.String())
			}
			return
		}
	case <-time.After(timeoutVal):
		fmt.Printf("%skatana batch timed out after %v, killing process%s\n", gray, timeoutVal, reset)
>>>>>>> 585fbcebeac7efd4988634e5867d1ba8e682d808
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return
	}

<<<<<<< HEAD
	// ۴. شمارش خطوط خروجی نهایی
=======
	// شمارش خطوط نتایج یافت شده
>>>>>>> 585fbcebeac7efd4988634e5867d1ba8e682d808
	file, _ := os.Open(katanaOutput)
	count := 0
	if file != nil {
		sc := bufio.NewScanner(file)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) != "" {
				count++
			}
		}
		file.Close()
	}

<<<<<<< HEAD
	fmt.Printf("%sdone for batch, results: %d saved to %s%s\n", gray, count, katanaOutput, reset)
=======
	// لاگ خلاصه‌ی موفقیت منطبق با درخواست شما
	fmt.Printf("%sdone for batch of %d URLs, results: %d lines saved to %s%s\n", gray, len(targets), count, katanaOutput, reset)
>>>>>>> 585fbcebeac7efd4988634e5867d1ba8e682d808
}

func main() {
	var outDir string
	var useJsluice bool
	var timeoutVal time.Duration
	var concurrency int
	var rateLimit int

	flag.StringVar(&outDir, "o", "results/katana", "Output directory")
<<<<<<< HEAD

	// نکته: اگر فلگ‌های دیگری مثل timeout یا jsluice در نسخه اصلی داری، اینجا تعریفشان کن
=======
	flag.BoolVar(&useJsluice, "jsluice", false, "Enable -jsluice flag (requires custom build tag)")
	// تایم‌اوت پیش‌فرض به ۴۵ دقیقه تغییر کرد
	flag.DurationVar(&timeoutVal, "timeout", 45*time.Minute, "Timeout duration for the entire batch (e.g., 45m, 1h, 2h)")
	// مقادیر جدید و داینامیک برای Batch Processing
	flag.IntVar(&concurrency, "c", 10, "Concurrency level (default 10 for batch)")
	flag.IntVar(&rateLimit, "rl", 50, "Rate limit (default 50 for batch)")
>>>>>>> 585fbcebeac7efd4988634e5867d1ba8e682d808
	flag.Parse()

	var targets []string
	if flag.NArg() > 0 {
		arg := flag.Arg(0)
		if info, err := os.Stat(arg); err == nil && !info.IsDir() {
			file, _ := os.Open(arg)
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
<<<<<<< HEAD
				// جلوگیری از اضافه شدن خطوط خالی
				val := strings.TrimSpace(scanner.Text())
				if val != "" {
					targets = append(targets, val)
=======
				if t := strings.TrimSpace(scanner.Text()); t != "" {
					targets = append(targets, t)
>>>>>>> 585fbcebeac7efd4988634e5867d1ba8e682d808
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
<<<<<<< HEAD
				val := strings.TrimSpace(scanner.Text())
				if val != "" {
					targets = append(targets, val)
=======
				if t := strings.TrimSpace(scanner.Text()); t != "" {
					targets = append(targets, t)
>>>>>>> 585fbcebeac7efd4988634e5867d1ba8e682d808
				}
			}
		}
	}

	if len(targets) == 0 {
		fmt.Println("Usage:")
		fmt.Println("  echo domain.com | nice_katana [flags]")
		fmt.Println("  nice_katana -jsluice -timeout 1h -c 20 -rl 100 domain.com")
		fmt.Println("  nice_katana -timeout 2h domains.txt")
		return
	}

<<<<<<< HEAD
	// متغیرهای رنگ برای لاگ
	gray := "\033[1;30m"
	reset := "\033[0m"

	// لاگ تایید گرفتن کل لیست
	fmt.Printf("%s[STARTUP] nice_katana processing batch size: %d URLs%s\n", gray, len(targets), reset)

	// حذف حلقه for و ارسال کل آرایه به تابع پردازش گروهی
	// اگر فلگ‌های دیگری مثل کانکارنسی یا تایم‌اوت داری، به پارامترهای این تابع اضافه‌شان کن
	runNiceKatanaBatch(targets, outDir)
}
=======
	// در main() دیگر نیازی به حلقه‌ی for نیست. کل لیست یک‌جا پردازش می‌شود.
	runNiceKatanaBatch(targets, outDir, useJsluice, timeoutVal, concurrency, rateLimit)
}
>>>>>>> 585fbcebeac7efd4988634e5867d1ba8e682d808
