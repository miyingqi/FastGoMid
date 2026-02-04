package FastGoMid

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = os.Getenv("JWT_SECRET")

type CustomClaims struct {
	UserID    uint   `json:"user_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

type AuthMid struct {
}

func NewAuthMid() *AuthMid {
	return &AuthMid{}
}

func (m *AuthMid) GenerateToken(userID uint, username, role string) (accessToken, refreshToken string, err error) {
	// 1. 生成 Access Token (有效期短)
	nowTime := time.Now()
	expTime := nowTime.Add(2 * time.Hour) // 2小时后过期

	accessClaims := CustomClaims{
		UserID:    userID,
		Username:  username,
		Role:      role,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expTime),
			IssuedAt:  jwt.NewNumericDate(nowTime),
			Issuer:    "fastgo",
		},
	}

	accessTokenObj, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}

	// 2. 生成 Refresh Token (有效期长)
	rtExpTime := nowTime.Add(7 * 24 * time.Hour) // 7天后过期

	refreshClaims := CustomClaims{
		UserID:    userID,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(rtExpTime),
			IssuedAt:  jwt.NewNumericDate(nowTime),
			Issuer:    "fastgo",
		},
	}

	refreshTokenObj, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}

	// TODO: 实际项目中，这里应该将 Refresh Token 存入 Redis 或数据库
	// key := fmt.Sprintf("refresh_token_%d", userID)
	// m.RedisClient.Set(ctx, key, refreshTokenObj, 7*24*time.Hour)

	return accessTokenObj, refreshTokenObj, nil
}

// ParseToken 解析 Token
func (m *AuthMid) ParseToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
