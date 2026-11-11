// Samorozpakowujący się instalator serwera społeczności lewicowYT dla Windows (.exe).
//
// Zawiera (go:embed) paczkę payload.zip z plikami serwera oraz install.ps1. Działanie:
//  1. pyta, gdzie zainstalować (domyślnie %USERPROFILE%\lewicowYT-serwer) — pomija pytanie, gdy podano -dir;
//  2. rozpakowuje pliki serwera (nadpisuje TYLKO pliki kodu; data\, engine\, engine-tor\, tools\, node_modules\ nie są w paczce);
//  3. uruchamia install.ps1 (pobiera brakujące: Node.js, Tor, FFmpeg, cjxl, acme-client — z weryfikacją SHA-256).
//
// Parametry własne:   -dir <katalog>   -nopause   -extract-only (tylko rozpakuj, bez install.ps1)   -version
// Wszystkie pozostałe (np. -Mode system -Tor no -Clean -Yes -CheckOnly) trafiają do install.ps1.
//
// NOTA DLA AUDYTORÓW: program nie łączy się z siecią sam z siebie — całe pobieranie robi install.ps1 (jawny, czytelny skrypt,
// który jest też w paczce). Plik .exe nie jest podpisany certyfikatem Authenticode, więc SmartScreen może pokazać ostrzeżenie.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed payload.zip
var payload []byte

// ustawiane przez -ldflags "-X main.version=..."
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	var dir string
	noPause, extractOnly := false, false
	var passthrough []string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch strings.ToLower(strings.TrimLeft(a, "-/")) {
		case "dir":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Brak wartosci po -dir.")
				return 2
			}
			i++
			dir = args[i]
		case "nopause":
			noPause = true
		case "extract-only":
			extractOnly = true
		case "version":
			fmt.Println("lewicowYT serwer spolecznosci — instalator", version)
			return 0
		case "help", "h", "?":
			usage()
			return 0
		default:
			passthrough = append(passthrough, a)
		}
	}

	fmt.Println("== lewicowYT — instalator serwera spolecznosci", version, "==")
	if dir == "" {
		def := defaultDir()
		fmt.Printf("Gdzie zainstalowac serwer?\n  [Enter] = %s\n  albo wpisz wlasna sciezke: ", def)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		line = strings.TrimSpace(strings.Trim(strings.TrimSpace(line), "\""))
		if line == "" {
			dir = def
		} else {
			dir = line
		}
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return fail(noPause, "Nieprawidlowa sciezka: %v", err)
	}
	n, err := extract(dir)
	if err != nil {
		return fail(noPause, "Rozpakowanie nie powiodlo sie: %v", err)
	}
	fmt.Printf("Rozpakowano %d plikow do: %s\n", n, dir)
	if extractOnly {
		pause(noPause)
		return 0
	}

	ps1 := filepath.Join(dir, "install.ps1")
	cmdArgs := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps1}, passthrough...)
	cmd := exec.Command("powershell.exe", cmdArgs...)
	cmd.Dir = dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			return fail(noPause, "Nie udalo sie uruchomic PowerShella: %v", err)
		}
	}
	if code == 0 {
		fmt.Printf("\nGotowe. Uruchom serwer: %s\n", filepath.Join(dir, "start.bat"))
	}
	pause(noPause)
	return code
}

func usage() {
	fmt.Println(`Uzycie: instalator.exe [-dir KATALOG] [-nopause] [-extract-only] [parametry install.ps1]
  -dir KATALOG   gdzie zainstalowac (bez pytania)
  -nopause       nie czekaj na Enter na koncu
  -extract-only  tylko rozpakuj pliki, nie uruchamiaj install.ps1
  parametry install.ps1:  -Mode local|system|ask   -Tor yes|no|ask   -Clean   -Yes   -CheckOnly`)
}

func defaultDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, "lewicowYT-serwer")
	}
	return "lewicowYT-serwer"
}

func fail(noPause bool, format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "BLAD: "+format+"\n", a...)
	pause(noPause)
	return 1
}

func pause(noPause bool) {
	if noPause {
		return
	}
	fmt.Print("\nNacisnij Enter, aby zamknac...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

// extract rozpakowuje paczke do dir; chroni przed wyjsciem poza katalog docelowy (zip-slip).
func extract(dir string) (int, error) {
	zr, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	base := filepath.Clean(dir) + string(os.PathSeparator)
	count := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		target := filepath.Join(dir, filepath.FromSlash(f.Name))
		if !strings.HasPrefix(target, base) {
			return count, fmt.Errorf("niedozwolona sciezka w paczce: %s", f.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return count, err
		}
		rc, err := f.Open()
		if err != nil {
			return count, err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return count, err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
