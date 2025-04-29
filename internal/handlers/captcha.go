package handlers

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	maxDifficulty = 3
	failsPerLevel = 2 // Number of fails before increasing difficulty
)

func numberToWords(n int) string {
	words := []string{"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
		"eleven", "twelve", "thirteen", "fourteen", "fifteen"}

	if n < len(words) {
		return words[n]
	}
	return strconv.Itoa(n)
}

func generateProblem(difficulty int) (problem string, answer int) {
	rand.Seed(time.Now().UnixNano())

	switch difficulty {
	case 1:
		a := rand.Intn(8) + 2
		b := rand.Intn(8) + 2
		if rand.Intn(2) == 0 {
			return numberToWords(a) + " multiplied by " + numberToWords(b), a * b
		} else {
			c := a * b
			return numberToWords(c) + " minus " + numberToWords(a), c - a
		}

	case 2:
		a := rand.Intn(6) + 2
		b := rand.Intn(6) + 2
		c := rand.Intn(3) + 2
		if rand.Intn(2) == 0 {
			return "(" + numberToWords(a) + " plus " + numberToWords(b) + ") multiplied by " + numberToWords(c), (a + b) * c
		} else {
			return numberToWords(a) + " multiplied by " + numberToWords(b) + " plus " + numberToWords(c), a*b + c
		}

	case 3:
		a := rand.Intn(5) + 2
		b := rand.Intn(5) + 2
		c := rand.Intn(5) + 2
		ops := []string{"plus", "multiplied by"}
		op1 := ops[rand.Intn(2)]
		op2 := ops[rand.Intn(2)]

		problem := numberToWords(a) + " " + op1 + " " + numberToWords(b) + " " + op2 + " " + numberToWords(c)

		if op1 == "multiplied by" && op2 == "plus" {
			return problem, a*b + c
		} else if op1 == "plus" && op2 == "multiplied by" {
			return problem, a + (b * c)
		} else if op1 == "multiplied by" && op2 == "multiplied by" {
			return problem, a * b * c
		} else {
			return problem, a + b + c
		}

	default:
		a := rand.Intn(6) + 2
		b := rand.Intn(6) + 2
		return numberToWords(a) + " multiplied by " + numberToWords(b), a * b
	}
}

func getDifficulty(session sessions.Session) int {
	failedAttempts := session.Get("captcha_fails")
	if failedAttempts == nil {
		return 1
	}

	difficulty := (failedAttempts.(int) / failsPerLevel) + 1
	if difficulty > maxDifficulty {
		difficulty = maxDifficulty
	}
	return difficulty
}

type CaptchaData struct {
	TargetSum  int   // The sum we're looking for
	Options    []int // Available individual numbers
	SessionID  string
	Difficulty int
}

func generateSumProblem(difficulty int) (string, int, []int) {
	// Generate target sum based on difficulty (between 5 and 15)
	targetSum := 5 + (difficulty * 2) + rand.Intn(5)

	// Always generate exactly 4 numbers
	options := make([]int, 4)

	// First, generate two numbers that sum to targetSum
	num1 := rand.Intn(targetSum-1) + 1
	num2 := targetSum - num1

	// Place our two correct numbers in the options
	options[0] = num1
	options[1] = num2

	// Generate two more random numbers that won't sum to targetSum
	used := make(map[int]bool)
	used[num1] = true
	used[num2] = true

	for i := 2; i < 4; i++ {
		for {
			num := rand.Intn(targetSum-1) + 1
			// Ensure the new number doesn't create another valid sum
			if !used[num] && num != targetSum-options[0] && num != targetSum-options[1] {
				options[i] = num
				used[num] = true
				break
			}
		}
	}

	// Shuffle the options
	rand.Shuffle(len(options), func(i, j int) {
		options[i], options[j] = options[j], options[i]
	})

	problem := fmt.Sprintf("Please select the numbers that sum to %d.", targetSum)
	return problem, targetSum, options
}

func GenerateCaptcha(c *gin.Context) {
	session := sessions.Default(c)
	difficulty := getDifficulty(session)

	problem, targetSum, options := generateSumProblem(difficulty)
	sessionID := generateSecureSessionID()

	// Store both target sum and options in session for validation
	session.Set("captcha_target", targetSum)
	session.Set("captcha_options", options)
	session.Set("captcha_session_id", sessionID)
	session.Set("captcha_difficulty", difficulty)
	session.Save()

	c.Set("captcha_problem", problem)
	c.Set("captcha_options", options)
	c.Set("captcha_session_id", sessionID)
	c.Set("captcha_difficulty", difficulty)
}

func generateSecureSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

func IncrementFailedAttempts(session sessions.Session) {
	fails := 0
	if f := session.Get("captcha_fails"); f != nil {
		fails = f.(int)
	}
	session.Set("captcha_fails", fails+1)
	session.Save()
}

func ResetFailedAttempts(session sessions.Session) {
	session.Delete("captcha_fails")
	session.Save()
}
